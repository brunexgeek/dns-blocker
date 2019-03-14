#define _POSIX_C_SOURCE 200112L

#include "defs.hh"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <list>
#include <fstream>

#include <signal.h>
#include <limits.h>
#include "nodes.hh"
#include "dns.hh"
#include "socket.hh"
#include "config.pg.hh"
#include "log.hh"
#include <mutex>
#include <thread>
#include <condition_variable>
#include <dns-blocker/errors.hh>
#include "monitor.hh"


#ifdef __WINDOWS__
#include <Windows.h>
#define PATH_SEPARATOR '\\'
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif


#define IP_EQUIVALENT(addr1,addr2) \
    ( ( (addr1) == (addr2) ) || ( DNS_IP_O1(addr1) == DNS_IP_O1(addr2) && DNS_IP_O1(addr1) == 127 ) )


struct Job
{
    Endpoint endpoint;
    dns_message_t request;

    Job( Endpoint &endpoint, dns_message_t &request )
    {
        this->endpoint = endpoint;
        this->request.swap(request);
    }
};


class Queue
{
    std::list<Job*> items;
    std::mutex lock;

    public:
        void push( Job *job )
        {
            std::lock_guard<std::mutex> guard(lock);
            items.push_back(job);
        }

        Job *pop()
        {
            std::lock_guard<std::mutex> guard(lock);
            if (items.size() == 0) return nullptr;
            Job *result = items.front();
            items.pop_front();
            return result;
        }
};


static UDP *conn = nullptr;

static struct
{
    std::string basePath;
    std::string blacklistFileName;
    Tree<uint8_t> blacklist;
    Tree<uint32_t> nameserver;
    /*std::string externalDNS;
    std::string bindAddress;*/
    uint32_t bindIPv4;
    //int port = 53;
    bool signal = false;
    std::string logPath;
    std::string dumpPath;
    DNSCache *cache = nullptr;
    std::string configFileName;
    Configuration config;
    Monitor monitor;

    struct
    {
        std::mutex mutex;
        std::condition_variable cond;
    } waiting;

} context;


static const char* getType( uint16_t type )
{
    switch (type)
    {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        default:             return "?";
    }
}


static bool main_initialize()
{
    if (context.config.binding().port() > 65535)
    {
        LOG_MESSAGE("Invalid port number %d\n", context.config.binding().port());
        return false;
    }

    context.bindIPv4 = UDP::hostToIPv4(context.config.binding().address());
	conn = new UDP();
	if (!conn->bind(context.config.binding().address(), (uint16_t) context.config.binding().port()))
    {
        #ifdef __WINDOWS__
		LOG_MESSAGE("Unable to bind to %s\n", context.config.binding().address().c_str());
		#else
		LOG_MESSAGE("Unable to bind to %s: %s\n", context.config.binding().address().c_str(), strerror(errno));
		#endif
        delete conn;
		conn = nullptr;
        return false;
    }

    context.cache = new DNSCache();
    bool found = false;
    for (auto it = context.config.external_dns().begin(); it != context.config.external_dns().end(); ++it)
    {
        if (it->targets.undefined())
        {
            context.cache->setDefaultDNS(it->address());
            found = true;
        }
        else
        {
            for (size_t i = 0; i < it->targets().size(); ++i)
            {
                context.cache->addTarget(it->targets()[i], it->address());
            }
        }
    }
    if (!found)
    {
        LOG_MESSAGE("Missing default external DNS\n");
        exit(1);
    }

    return true;
}


static int main_terminate()
{
	conn->close();
	delete conn;
	conn = nullptr;
    delete context.cache;
	context.cache = nullptr;
    return 0;
}


bool main_loadRules(
    const std::string &fileName )
{
    if (fileName.empty()) return false;

    LOG_MESSAGE("\nLoading rules from '%s'\n", fileName.c_str());

    context.blacklist.clear();

    std::ifstream rules(fileName.c_str());
    if (!rules.good()) return false;

    std::string line;

    while (!rules.eof())
    {
        std::getline(rules, line);
        if (line.empty()) continue;

        // we have a comment?
        const char *ptr = line.c_str();
        while (*ptr == ' ' || *ptr == '\t') ++ptr;
        if (*ptr == '#') continue;

        int result = context.blacklist.add(line, 0);
        if (result == DNSBERR_OK)
            LOG_MESSAGE("  Added '%s'\n", line.c_str());
        else
        if (result == DNSBERR_DUPLICATED_RULE)
            LOG_MESSAGE("  Duplicated '%s'\n", line.c_str());
        else
            LOG_MESSAGE("  Invalid rule '%s'\n", line.c_str());
    }

    rules.close();

    LOG_MESSAGE("Generated tree with %d nodes (%2.3f KiB)\n\n", context.blacklist.size(),
        (float) context.blacklist.memory() / 1024.0F);

    return true;
}


static bool main_returnError(
    const dns_message_t &request,
    int rcode,
    const Endpoint &endpoint )
{
    uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };
    BufferIO bio(buffer, 0, DNS_BUFFER_SIZE);
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags |= DNS_FLAG_QR;
    response.questions.push_back(request.questions[0]);
    response.header.rcode = (uint8_t) rcode;
    response.write(bio);
    return conn->send(endpoint, bio.buffer, bio.cursor());
}


#ifdef ENABLE_DNS_CONSOLE
static void main_control( const std::string &command )
{
    if (command == "reload@dnsblocker")
        main_loadRules(context.blacklistFileName);
    else
    if (command == "dump@dnsblocker")
    {
        LOG_MESSAGE("\nDumping DNS cache to '%s'\n\n", context.dumpPath.c_str());
        context.cache->dump(context.dumpPath);
    }
}
#endif


static void main_process( int num, Queue *pending, std::mutex *lock, std::condition_variable *cond )
{
    std::unique_lock<std::mutex> guard(*lock);
    //std::string lastName;

    const char *COLOR_RED = "\033[31m";
    const char *COLOR_YELLOW = "\033[33m";
    const char *COLOR_RESET = "\033[39m";

#if !defined(_WIN32) && !defined(_WIN64)
    if (!isatty(STDIN_FILENO))
#endif
    {
        COLOR_RED = "";
        COLOR_YELLOW = "";
        COLOR_RESET = "";
    }

    while (!context.signal)
    {
        Job *job = pending->pop();
        if (job == nullptr)
        {
            cond->wait(guard);
            continue;
        }

        Endpoint &endpoint = job->endpoint;
//LOG_MESSAGE("T%d Processing request from  %08X\n", num, endpoint.address);
        dns_message_t &request = job->request;
//LOG_MESSAGE("T%d Got job   %s\n", num, request.questions[0].qname.c_str());
        uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };

        #ifdef ENABLE_DNS_CONSOLE
        // check whether the message carry a remote command
        if (IP_EQUIVALENT(context.bindIPv4, endpoint.address) &&
            request.questions[0].qname.find("@dnsblocker") != std::string::npos)
        {
            main_control(request.questions[0].qname);
            main_returnError(request, DNS_RCODE_NOERROR, endpoint);
            delete job;
            continue;
        }
        #endif

        // check whether the domain is blocked
        bool isBlocked = context.blacklist.match(request.questions[0].qname) != nullptr;
        uint32_t address = 0, dnsAddress = 0;
        int result = 0;

        // if the domain is not blocked, we retrieve the IP address from the cache
        if (!isBlocked)
        {
            // assume NXDOMAIN for domains without periods (e.g. local host names)
            // otherwise we try the external DNS
            if (request.questions[0].qname.find('.') == std::string::npos)
                result = DNSB_STATUS_NXDOMAIN;
            else
            if (request.header.flags & DNS_FLAG_RD)
                result = context.cache->resolve(request.questions[0].qname, &dnsAddress, &address);
            else
                result = DNSB_STATUS_NXDOMAIN;
        }
        else
            address = DNS_BLOCKED_ADDRESS;

        if (context.config.monitoring())
        {
            // print some information about the request
            //if (lastName != request.questions[0].qname)
            {
                const char *status = "DE";
                const char *color = COLOR_RED;
                if (result == DNSB_STATUS_CACHE)
                {
                    status = "CA";
                    color = COLOR_RESET;
                }
                else
                if (result == DNSB_STATUS_RECURSIVE)
                {
                    status = "RE";
                    color = COLOR_RESET;
                }
                else
                if (result == DNSB_STATUS_FAILURE)
                {
                    status = "FA";
                    color = COLOR_YELLOW;
                }
                else
                if (result == DNSB_STATUS_NXDOMAIN)
                {
                    status = "NX";
                    color = COLOR_YELLOW;
                }

                Event event;
                event.time = 0;
                event.source = endpoint.address;
                event.resolver = dnsAddress;
                event.address = address;
                event.status = status;
                event.host = request.questions[0].qname;
                context.monitor.push(event);

                //lastName = request.questions[0].qname;
                LOG_TIMED("%sT%d  %-15s  %s  %-15s  %-15s  %s%s\n",
                    color,
                    num,
                    Endpoint::addressToString(endpoint.address).c_str(),
                    status,
                    Endpoint::addressToString(dnsAddress).c_str(),
                    Endpoint::addressToString(address).c_str(),
                    request.questions[0].qname.c_str(),
                    COLOR_RESET);
            }
        }

        // decide whether we have to include an answer
        if (!isBlocked && result != DNSB_STATUS_CACHE && result != DNSB_STATUS_RECURSIVE)
        {
            if (result == DNSB_STATUS_NXDOMAIN)
                main_returnError(request, DNS_RCODE_NXDOMAIN, endpoint);
            else
                main_returnError(request, DNS_RCODE_SERVFAIL, endpoint);
        }
        else
        {
            // response message
            BufferIO bio = BufferIO(buffer, 0, DNS_BUFFER_SIZE);
            dns_message_t response;
            response.header.id = request.header.id;
            response.header.flags |= DNS_FLAG_QR;
            if (request.header.flags & DNS_FLAG_RD)
            {
                response.header.flags |= DNS_FLAG_RA;
                response.header.flags |= DNS_FLAG_RD;
            }
            // copy the request question
            response.questions.push_back(request.questions[0]);
            dns_record_t answer;
            answer.qname = request.questions[0].qname;
            answer.type = request.questions[0].type;
            answer.clazz = request.questions[0].clazz;
            answer.ttl = DNS_ANSWER_TTL;
            answer.rdata = address;
            response.answers.push_back(answer);

            response.write(bio);
            //sendto(socketfd, bio.buffer, bio.cursor(), 0, (struct sockaddr *) &clientAddress, addrLen);
            conn->send(endpoint, bio.buffer, bio.cursor());
        }

        delete job;
    }
}


static void main_loop()
{
    std::string lastName;
    uint8_t buffer[DNS_BUFFER_SIZE] = { 0 };
    Endpoint endpoint;
    Queue pending;
    std::mutex lock;
    std::thread *pool[2];
    std::condition_variable cond;

    for (size_t i = 0; i < NUM_THREADS; ++i)
        pool[i] = new std::thread(main_process, i + 1, &pending, &lock, &cond);

    while (true)
    {
        if (context.signal)
        {
            LOG_MESSAGE("Received signal\n");
            break;
        }

        // receive the UDP message
        BufferIO bio(buffer, 0, DNS_BUFFER_SIZE);
        if (!conn->receive(endpoint, bio.buffer, &bio.size)) continue;
//LOG_MESSAGE("Request from  %08X\n", endpoint.address);
        // parse the message
        dns_message_t request;
        request.read(bio);

        // ignore messages with the number of questions other than 1
        if (request.questions.size() != 1 || request.questions[0].type != DNS_TYPE_A)
        {
            main_returnError(request, DNS_RCODE_REFUSED, endpoint);
            continue;
        }

//LOG_MESSAGE("New job   %s\n", request.questions[0].qname.c_str());
        pending.push( new Job(endpoint, request) );
        cond.notify_all();
    }

    for (size_t i = 0; i < NUM_THREADS; ++i)
    {
        cond.notify_all();
        pool[i]->join();
        delete pool[i];
    }
}


static std::string main_realPath( const std::string &path )
{
	if (path.empty()) return "";

	#ifdef __WINDOWS__

	char temp[MAX_PATH];
	int result = GetFullPathName( path.c_str(), MAX_PATH, temp, NULL);
	if (result == 0 || result > MAX_PATH) return "";
	return temp;

	#else

    char temp[PATH_MAX];
    if (realpath(path.c_str(), temp) == nullptr) return "";
    return temp;

	#endif
}

static void daemonize( int argc, char **argv )
{
	#ifdef __WINDOWS__

	std::string command = main_realPath(argv[0]);
	int flags = 0;
	char arguments[1024];
	strncpy_s(arguments, command.c_str(), sizeof(arguments));
	strncat_s(arguments, " ", sizeof(arguments));
	strncat_s(arguments, argv[1], sizeof(arguments));
	if (argc == 3)
	{
		strncat_s(arguments, " ", sizeof(arguments));
		strncat_s(arguments, argv[2], sizeof(arguments));
		flags |= CREATE_NO_WINDOW;
	}
	std::cerr << "Running with '" << arguments << "'" << std::endl;
	STARTUPINFOA si;
    PROCESS_INFORMATION pi;
	ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcessA(command.c_str(), arguments, nullptr, nullptr, FALSE, flags,
		nullptr, nullptr, &si, &pi);
	exit(1);

	#else

	(void) argc;
	(void) argv;
    pid_t pid;

    // fork the parent process
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // close opened file descriptors
    for (long x = sysconf(_SC_OPEN_MAX); x>=0; x--) close ( (int) x);

	#endif
}


#ifdef __WINDOWS__

static BOOL WINAPI main_signalHandler(
  _In_ DWORD dwCtrlType )
{
	(void) dwCtrlType;
	context.signal = true;
	return TRUE;
}

#else

static void main_signalHandler(
	int handle )
{
	(void) handle;
	context.signal = true;
}

#endif


void main_usage()
{
    std::cout << "Usage: dnsblocker <configuration> [ <log directory> ]\n";
    exit(EXIT_FAILURE);
}


void main_error( const std::string &message )
{
    std::cerr << "ERROR: " << message << std::endl;
    exit(EXIT_FAILURE);
}

void main_parseArguments(
    int argc,
    char **argv )
{
	if (argc != 2 && argc != 3) main_usage();

	context.configFileName = argv[1];
    if (argc == 3)
	{
        context.logPath = main_realPath(argv[2]);
		context.logPath += PATH_SEPARATOR;
        context.logPath += LOG_FILENAME;

        context.dumpPath = main_realPath(argv[2]);
        context.dumpPath += PATH_SEPARATOR;
        context.dumpPath += LOG_CACHE_DUMP;
    }

    if (context.configFileName.empty())
        main_error("missing configuration file");
}


Configuration main_defaultConfig()
{
    Configuration config;
    config.daemon(false);
    config.monitoring(false);
    config.binding().port(53);
    config.binding().address("127.0.0.2");

    return config;
}


static std::string main_basePath( const std::string &path )
{
	std::string result;

	#ifdef __WINDOWS__

	size_t pos = path.rfind('\\');
    if (pos == std::string::npos)
        result = ".\\";
    else
        result = path.substr(0, pos);

	#else

	size_t pos = path.rfind('/');
    if (pos == std::string::npos)
        result = '/';
    else
        result = path.substr(0, pos);

	#endif

    return result;
}


void main_prepare()
{
    // extract the base path from the configuration file name
    context.basePath = context.configFileName = main_realPath(context.configFileName);
    if (context.configFileName.empty())
    {
        LOG_MESSAGE("Invalid configuration path '%s'\n", context.configFileName.c_str());
        exit(1);
    }
    context.basePath = main_basePath(context.configFileName);
    // change the current path
	#ifdef __WINDOWS__
	SetCurrentDirectory(context.basePath.c_str());
	#else
	chdir(context.basePath.c_str());
	#endif

    context.config = main_defaultConfig();

    // load configuration
    std::ifstream in(context.configFileName.c_str());
    Configuration::ErrorInfo err;
    if (!in.good() || !context.config.deserialize(in, false, &err))
    {
        LOG_MESSAGE("ERROR: Unable to load configuration from '%s'\n", context.configFileName.c_str());
        if (!err.message.empty())
            LOG_MESSAGE("ERROR: %s at %d:%d\n", err.message.c_str(), err.line, err.column);
        exit(1);
    }
    in.close();

    // get the absolute path of the input file
    context.blacklistFileName = main_realPath(context.config.blacklist());
    if (context.blacklistFileName.empty())
    {
        LOG_MESSAGE("Invalid blacklist file '%s'\n", context.config.blacklist().c_str());
        exit(1);
    }

    if (context.config.external_dns.undefined())
    {
        LOG_MESSAGE("At least one external DNS is required '%s'\n", context.config.blacklist().c_str());
        exit(1);
    }

    LOG_MESSAGE("    Base path: %s\n", context.basePath.c_str());
    LOG_MESSAGE("Configuration: %s\n", context.configFileName.c_str());
    LOG_MESSAGE("    Blacklist: %s\n", context.blacklistFileName.c_str());
    LOG_MESSAGE(" External DNS: ");
    for (auto it = context.config.external_dns().begin(); it != context.config.external_dns().end(); ++it)
        LOG_MESSAGE("%s ", it->address().c_str());
    LOG_MESSAGE("\n");
    LOG_MESSAGE("      Address: %s\n", context.config.binding().address().c_str());
    LOG_MESSAGE("         Port: %d\n", context.config.binding().port());
}


int main( int argc, char** argv )
{
    main_parseArguments(argc, argv);

    if (context.config.daemon()) daemonize(argc, argv);
    Log::instance = new Log( context.logPath.c_str() );

    LOG_MESSAGE("DNS Blocker %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

    main_prepare();

    #ifdef __WINDOWS__
    //SetConsoleCtrlHandler(main_signalHandler, TRUE);
    #else
    // install the signal handler to stop the server with CTRL + C
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGUSR2);
    sigaddset(&act.sa_mask, SIGUSR1);
    sigaddset(&act.sa_mask, SIGINT);
    act.sa_flags = 0;
    act.sa_handler = main_signalHandler;
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    #endif

    if (main_initialize())
    {
        if (main_loadRules(context.blacklistFileName))
        {
            context.monitor.start();
            main_loop();
        }
        else
            LOG_MESSAGE("Unable to load rules from '%s'\n", context.blacklistFileName.c_str());
        main_terminate();
    }

    LOG_MESSAGE("\nTerminated\n");
    delete Log::instance;
    return 0;
}
