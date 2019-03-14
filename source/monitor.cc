#include <webster/api.h>
#include "monitor.hh"


Event::Event()
{
}

Event::Event( const Event &that )
{
    *this = that;
}

Event::Event( Event &&that )
{
    this->time = that.time;
    this->source = that.source;
    this->resolver = that.resolver;
    this->address = that.address;
    this->status.swap(that.status);
    this->host.swap(that.host);
}

Event &Event::operator=( const Event &that )
{
    this->time = that.time;
    this->source = that.source;
    this->resolver = that.resolver;
    this->address = that.address;
    this->status = that.status;
    this->host = that.host;
    return *this;
}


Monitor::Monitor()
{
}

Monitor::~Monitor()
{
}

void Monitor::push( const Event &event )
{
    std::unique_lock<std::mutex> guard(listMutex_);
    if (events_.size() > MAX_ENTRIES)
        events_.resize(MAX_ENTRIES - 1);
    events_.push_back(event);
    cond_.notify_all();
}

bool Monitor::pop( Event &event )
{
    std::unique_lock<std::mutex> guard(listMutex_);
    if (events_.size() > 0)
    {
        event = events_.front();
        events_.pop_front();
        return true;
    }
    return false;
}

void Monitor::wait()
{
    std::unique_lock<std::mutex> guard(condMutex_);
    cond_.wait_for(guard, std::chrono::seconds(10));
}

void Monitor::enumerate( void *data )
{
    std::unique_lock<std::mutex> guard(listMutex_);
    for (auto it = events_.begin(); it != events_.end(); ++it)
    {
        webster_message_t *response = (webster_message_t*) data;
        WebsterWriteString(response, "<tr><td></td><td></td><td>");
        WebsterWriteString(response, it->status.c_str());
        WebsterWriteString(response, "</td><td></td><td>");
        WebsterWriteString(response, it->host.c_str());
        WebsterWriteString(response, "</td></tr>");
    }
}

static int monitor_serverHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
	Monitor *monitor = (Monitor*) data;

	webster_event_t event;
	const webster_target_t *target = NULL;
	int result = 0;
	int method = 0;

	do
	{
		// wait for some request data
		result = WebsterWaitEvent(request, &event);
		//printf("WebsterWaitEvent = %d\n", result);
		if (result == WBERR_COMPLETE) break;
		if (result == WBERR_NO_DATA) continue;
		if (result != WBERR_OK) return 0;
	} while (1);

	// doing it again, but not necessary if the first call succeed
	result = WebsterGetTarget(request, &target);
	if (result != WBERR_OK) return result;
	result = WebsterGetMethod(request, &method);
	if (result != WBERR_OK) return result;

    WebsterSetStatus(response, 200);
    WebsterSetStringField(response, "Content-Type", "text/html");

    WebsterWriteString(response, "<html><head><title>");
    WebsterWriteString(response, "bla");
    WebsterWriteString(response, "</title></head><body>");

    WebsterWriteString(response, "<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>");
    WebsterWriteString(response, "<table><tr><th>Source</th><th>DNS</th><th>Status</th><th>Address</th><th>Host</th></tr>");
	monitor->enumerate(response);
	WebsterWriteString(response, "</body></table></html>");

	WebsterFinish(response);
	return WBERR_OK;
}

void Monitor::threadProc( Monitor *monitor )
{
    WebsterInitialize(NULL, NULL);
    webster_server_t *server = NULL;
	if (WebsterCreate(&server, 100) == WBERR_OK)
	{
		if (WebsterStart(server, "0.0.0.0", 7000) == WBERR_OK)
		{
			while (/*serverState == SERVER_RUNNING*/true)
			{
				webster_client_t *remote = NULL;
				int result = WebsterAccept(server, &remote);
				if (result == WBERR_OK)
				{
					WebsterCommunicateURL(remote, NULL, monitor_serverHandler, monitor);
					WebsterDisconnect(remote);
				}
				else
				if (result != WBERR_TIMEOUT) break;
			}
		}
		WebsterDestroy(server);
	}
	WebsterTerminate();
}


void Monitor::start()
{
    thread_ = std::thread(threadProc, this);
}

void stop()
{

}