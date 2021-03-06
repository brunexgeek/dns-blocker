#include "process.hh"
#include "log.hh"
#include <stdexcept>
#include <limits.h>
#include <chrono>

#ifdef __WINDOWS__
#include <Windows.h>
#define PATH_SEPARATOR '\\'
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif

namespace dnsblocker {

Processor::Processor( const Configuration &config ) : config_(config), running_(false), useHeuristics_(false),
    useFiltering_(true)
{
    if (config.binding.port() > 65535)
    {
        LOG_MESSAGE("Invalid port number %d\n", config.binding.port);
        throw std::runtime_error("Invalid port number");
    }
    useHeuristics_ = config.use_heuristics();

    bindIP_.type = ADDR_TYPE_A;
    bindIP_.ipv4 = UDP::hostToIPv4(config.binding.address);
	conn_ = new UDP();
	if (!conn_->bind(config.binding.address, (uint16_t) config.binding.port))
    {
        #ifdef __WINDOWS__
		LOG_MESSAGE("Unable to bind to %s:%d\n", config.binding.address.c_str(), config.binding.port());
		#else
		LOG_MESSAGE("Unable to bind to %s:%d: %s\n", config.binding.address.c_str(), config.binding.port(), strerror(errno));
		#endif
        delete conn_;
		conn_ = nullptr;
        throw std::runtime_error("Unable to bind");
    }

    cache_ = new DNSCache(config.cache.limit(), config.cache.ttl);
    bool found = false;
    for (auto it = config.external_dns.begin(); it != config.external_dns.end(); ++it)
    {
        if (it->targets.empty())
        {
            cache_->setDefaultDNS(it->address, it->name);
            found = true;
        }
        else
        {
            for (size_t i = 0; i < it->targets.size(); ++i)
            {
                cache_->addTarget(it->targets[i], it->address, it->name);
            }
        }
    }
    if (!found)
    {
        LOG_MESSAGE("Missing default external DNS\n");
        throw std::runtime_error("Missing default external DNS");
    }

    loadRules(config_.blacklist, blacklist_);
    loadRules(config_.whitelist, whitelist_);
}


Processor::~Processor()
{
	conn_->close();
	delete conn_;
	conn_ = nullptr;
    delete cache_;
	cache_ = nullptr;
}


void Processor::push( Job *job )
{
    std::lock_guard<std::mutex> guard(mutex_);
    pending_.push_back(job);
}

Job *Processor::pop()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (pending_.size() == 0) return nullptr;
    Job *result = pending_.front();
    pending_.pop_front();
    return result;
}


bool Processor::loadRules(
    const std::vector<std::string> &fileNames,
    Tree<uint8_t> &tree )
{
    if (fileNames.empty()) return false;

    tree.clear();

    for (auto it = fileNames.begin(); it != fileNames.end(); ++it)
    {
        int c = 0;
        LOG_MESSAGE("Loading rules from '%s'\n", it->c_str());

        std::ifstream rules(it->c_str());
        if (!rules.good()) return false;

        std::string line;

        while (!rules.eof())
        {
            std::getline(rules, line);
            if (line.empty()) continue;

            // remove comments
            size_t pos = line.find('#');
            if (pos != std::string::npos) line = line.substr(0, pos);

            int result = tree.add(line, 0, &line);
            if (line.empty()) continue;

            if (result == DNSBERR_OK)
            {
                ++c;
                continue;
            }
            else
            if (result == DNSBERR_DUPLICATED_RULE)
                LOG_MESSAGE("  [!] Duplicated '%s'\n", line.c_str());
            else
                LOG_MESSAGE("  [!] Invalid rule '%s'\n", line.c_str());
        }

        rules.close();
        LOG_MESSAGE("  Loaded %d rules\n", c);
    }

    float mem = (float) tree.memory();
    const char *unit = "bytes";
    if (mem > 1024 * 1024)
    {
        mem /= 1024 * 1024;
        unit = "MiB";
    }
    else
    if (mem > 1024)
    {
        mem /= 1024;
        unit = "KiB";
    }
    LOG_MESSAGE("Generated tree with %d nodes (%2.3f %s)\n\n", tree.size(), mem, unit);

    return true;
}

#ifdef ENABLE_DNS_CONSOLE
void Processor::console( const std::string &command )
{
    if (command == "reload")
    {
        loadRules(config_.blacklist, blacklist_);
        loadRules(config_.whitelist, whitelist_);
        cache_->reset(); // TODO: we really need this?
    }
    else
    if (command == "ef")
    {
        LOG_MESSAGE("\nFiltering enabled!\n");
        useFiltering_ = true;
    }
    else
    if (command == "df")
    {
        LOG_MESSAGE("\nFiltering disabled!\n");
        useFiltering_ = false;
    }
    else
    if (command == "eh")
    {
        LOG_MESSAGE("\nHeuristics enabled!\n");
        useHeuristics_ = true;
    }
    else
    if (command == "dh")
    {
        LOG_MESSAGE("\nHeuristics disabled!\n");
        useHeuristics_ = false;
    }
    else
    if (command == "dump")
    {
        LOG_MESSAGE("\nDumping DNS cache to '%s'\n\n", config_.dump_path_.c_str());
        cache_->dump(config_.dump_path_);
    }
}
#endif


static void blockAddress( int type, Address &address )
{
    static const uint16_t IPV6_ADDRESS[] = DNS_BLOCKED_IPV6_ADDRESS;
    address.type = type;
    if (type == DNS_TYPE_A)
        address.ipv4 = DNS_BLOCKED_IPV4_ADDRESS;
    else
        memcpy(address.ipv6, IPV6_ADDRESS, sizeof(IPV6_ADDRESS));
}


bool Processor::sendError(
    const dns_message_t &request,
    int rcode,
    const Endpoint &endpoint )
{
    if (request.questions.size() == 0) return false;
    buffer bio;
    dns_message_t response;
    response.header.id = request.header.id;
    response.header.flags |= DNS_FLAG_QR;
    response.questions.push_back(request.questions[0]);
    response.header.rcode = (uint8_t) rcode;
    response.write(bio);
    return conn_->send(endpoint, bio.data(), bio.cursor());
}

bool Processor::isRandomDomain( std::string name )
{
    if (name.find("www.") == 0)
        name = name.c_str() + 4;
    if (name.find("cloudfront") == std::string::npos)
    {
        int i = 0;
        for (char c : name) if (c == '.') ++i;
        if (i > 1) return false;
    }

    auto pos = name.find('.');
    if (pos == std::string::npos) return false;
    name = name.substr(0, pos);

    if (name.length() < 10) return false;

    int gon = 0; // group of numbers a0bc32de1 = 3
    char gs = 0; // group size
    char bgs = 0; // biggest group size
    int vc = 0; // vowel count
    int cc = 0; // consonant count

    const char *c = name.c_str();
    while (*c != 0)
    {
        if (isdigit(*c))
            ++gs;
        else
        if (strchr("aeiouAEIOU", *c) != nullptr)
            ++vc;
        else
            ++cc;
        if (gs > 0)
        {
            ++gon;
            if (bgs < gs) bgs = gs;
            gs = 0;
        }
        ++c;
    }

    //if (gon == 0) return false; // require digits
    if (bgs > 4) return true; // at least 5 digits in the biggest group
    if (gon > 1) return true; // at least 2 groups
    if ((float) vc / (float) name.length() < 0.3F) return true; // less than 30% of vowels
    return false;
}

void Processor::process(
    Processor *object,
    int num,
    std::mutex *mutex,
    std::condition_variable *cond )
{
    (void) num;
    std::unique_lock<std::mutex> guard(*mutex);

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

    while (object->running_)
    {
        Job *job = object->pop();
        if (job == nullptr)
        {
            cond->wait_for(guard, std::chrono::seconds(1));
            continue;
        }

        Endpoint &endpoint = job->endpoint;
        dns_message_t &request = job->request;

        // check whether the domain is blocked
        bool isHeuristic = false;
        bool isBlocked = false;
        if (object->useFiltering_)
        {
            if (object->whitelist_.match(request.questions[0].qname) == nullptr)
            {
                if (object->useHeuristics_)
                    isBlocked = isHeuristic = isRandomDomain(request.questions[0].qname);
                if (!isBlocked)
                    isBlocked = object->blacklist_.match(request.questions[0].qname) != nullptr;
            }
        }
        Address address, dnsAddress;
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
                result = object->cache_->resolve(request.questions[0].qname, request.questions[0].type, dnsAddress, address);
            else
                result = DNSB_STATUS_NXDOMAIN;
        }
        else
        {
            blockAddress(request.questions[0].type, address);
        }

        // print information about the request
        auto flags = (int32_t) object->config_.monitoring_;
        const char *status = nullptr;
        const char *color = COLOR_RED;

        if (isBlocked && flags & MONITOR_SHOW_DENIED)
        {
            status = "DE";
            color = COLOR_RED;
        }
        else
        if (result == DNSB_STATUS_CACHE && flags & MONITOR_SHOW_CACHE)
        {
            status = "CA";
            color = COLOR_RESET;
        }
        else
        if (result == DNSB_STATUS_RECURSIVE && flags & MONITOR_SHOW_RECURSIVE)
        {
            status = "RE";
            color = COLOR_RESET;
        }
        else
        if (result == DNSB_STATUS_FAILURE && flags & MONITOR_SHOW_FAILURE)
        {
            status = "FA";
            color = COLOR_YELLOW;
        }
        else
        if (result == DNSB_STATUS_NXDOMAIN && flags & MONITOR_SHOW_NXDOMAIN)
        {
            status = "NX";
            color = COLOR_YELLOW;
        }

        if (status != nullptr)
        {
            std::string addr;
            if (!isBlocked) addr = address.toString(true);

            #ifdef DNS_IPV6_EXPERIMENT
            static const char *FORMAT = "%s%-40s  %s %c  %-8s  %-40s  %s%s\n";
            #else
            static const char *FORMAT = "%s%-15s  %s %c  %-8s  %-15s  %s%s\n";
            #endif
            LOG_TIMED(FORMAT,
                color,
                endpoint.address.toString().c_str(),
                status,
                (request.questions[0].type == ADDR_TYPE_AAAA) ? '6' : '4',
                (isHeuristic) ? "*" : dnsAddress.name.c_str(),
                addr.c_str(),
                request.questions[0].qname.c_str(),
                COLOR_RESET);
        }

        // decide whether we have to include an answer
        if (!isBlocked && result != DNSB_STATUS_CACHE && result != DNSB_STATUS_RECURSIVE)
        {
            if (result == DNSB_STATUS_NXDOMAIN)
                object->sendError(request, DNS_RCODE_NXDOMAIN, endpoint);
            else
                object->sendError(request, DNS_RCODE_SERVFAIL, endpoint);
        }
        else
        {
            // response message
            buffer bio;
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
            object->conn_->send(endpoint, bio.data(), bio.cursor());
        }

        delete job;
    }
}


struct process_unit_t
{
    std::thread *thread;
    std::mutex mutex;
};


void Processor::run()
{
    std::string lastName;
    Endpoint endpoint;
    process_unit_t pool[NUM_THREADS];
    std::condition_variable cond;

    running_ = true;
    for (int i = 0; i < NUM_THREADS; ++i)
        pool[i].thread = new std::thread(process, this, i + 1, &pool[i].mutex, &cond);

    while (running_)
    {
        // receive the UDP message
        buffer bio;
        size_t size = bio.size();
        if (!conn_->receive(endpoint, bio.data(), &size, 2000)) continue;
        bio.resize(size);

        // parse the message
        dns_message_t request;
        request.read(bio);

        // ignore messages with the number of questions other than 1
        int type = 0;
        if (request.questions.size() == 1) type = request.questions[0].type;
        #ifdef DNS_IPV6_EXPERIMENT
        if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA)
        #else
        if (type != DNS_TYPE_A)
        #endif
        {
            sendError(request, DNS_RCODE_REFUSED, endpoint);
            continue;
        }

        push( new Job(endpoint, request) );
        cond.notify_all();
    }

    for (size_t i = 0; i < NUM_THREADS; ++i)
    {
        cond.notify_all();
        pool[i].thread->join();
        delete pool[i].thread;
    }
}


bool Processor::finish()
{
    if (!running_) return true;
    running_ = false;
    return false;
}

}