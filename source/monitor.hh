#ifndef DNSB_MONITOR_HH
#define DNSB_MONITOR_HH


#include <stdint.h>
#include <string>
#include <list>
#include <mutex>
#include <thread>
#include <condition_variable>


struct Event 
{
    uint32_t time;
    uint32_t source;
    uint32_t resolver;
    uint32_t address;
    std::string status;
    std::string host;

    Event();
    Event( const Event &that );
    Event( Event &&that );
    Event &operator=( const Event &that );
};

class Monitor;

typedef void MonitorThreadProc( Monitor &monitor );

class Monitor 
{
    public:
        static const size_t MAX_ENTRIES = 1000;

        Monitor();
        ~Monitor();
        void push( const Event &event );
        bool pop( Event &event );
        void wait();
        void start();
        void stop();
        void enumerate( void * );

    private:
        std::mutex condMutex_;
        std::mutex listMutex_;
        std::condition_variable cond_;
        std::list<Event> events_;
        std::thread thread_;

        static void threadProc( Monitor *monitor );
};



#endif // DNSB_MONITOR_HH