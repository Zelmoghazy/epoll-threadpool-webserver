#pragma once 

#include <sys/epoll.h>

#include <Socket.h>
#include <ServerException.h>
#include <functional>

#include <ThreadPool.h>
#include <HTTP.h>


struct EventPoll
{
    Socket socket;
    ThreadPool thread_pool_; 

    int epoll_fd;

    std::function<void(req_context*)> client_handler_ = nullptr;

    static constexpr int MAX_EVENTS     = 32;

    EventPoll(const char *ip, const char *port, std::function<void(req_context*)> client_handler);
    EventPoll(const char* port,  std::function<void(req_context*)> client_handler);
    ~EventPoll();

    /* 
        No Reason to ever be copied or moved 
     */
    EventPoll(const EventPoll&) = delete;
    EventPoll& operator=(const EventPoll&) = delete;
    EventPoll(EventPoll&&) = delete;
    EventPoll& operator=(EventPoll&&) = delete;

    void register_fd(int fd, uint32_t event_flags);
    int register_fd_ctx(req_context *c, uint32_t event_flags);
    void rm_fd(int fd);
    void mod_fd_read(int fd);
    void mod_fd_write(int fd);
    static void mod_fd_read_ctx(req_context *c);
    static void mod_fd_write_ctx(req_context *c);
    void event_loop();
    void handle_new_connections();
    void handle_client_data(void* data);
};