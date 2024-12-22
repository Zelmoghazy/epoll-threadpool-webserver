#include <Server.h>

EventPoll::EventPoll(const char *ip, const char *port, std::function<void(req_context*)> client_handler): client_handler_(client_handler)
{
    socket.tcp_socket(ip, port);
    socket.wait_connection();

    // creates a new epoll instance and returns a file descriptor referring to that instance.
    if ((epoll_fd = epoll_create1(0)) < 0) {
        throw ServerException(std::string("Failed to create epoll instance") +  std::strerror(errno));
    }

    // Add listener socket to epoll, register it in edge triggered mode 
    register_fd(socket.get_socket(), (EPOLLIN | EPOLLET));
}

EventPoll::EventPoll(const char* port,  std::function<void(req_context*)> client_handler) : EventPoll(NULL,port,client_handler){}

EventPoll::~EventPoll() 
{
    if (epoll_fd >= 0) {
        close(epoll_fd);
    }
}

void EventPoll::register_fd(int fd, uint32_t event_flags)
{
    struct epoll_event ev;
    ev.events = event_flags;
    ev.data.fd = fd;

    // registering interest in a particular file descriptor
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) 
    {
        throw ServerException(std::string("Failed to add listener to epoll") +  std::strerror(errno));
    }
}

int EventPoll::register_fd_ctx(req_context *c, uint32_t event_flags)
{
    struct epoll_event ev;
    ev.events = event_flags;
    ev.data.ptr = c;

    // registering interest in a particular file descriptor
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->connfd, &ev) < 0) 
    {
        std::cerr << "Failed to register a file descriptor" << std::strerror(errno) << std::endl;
        return -1;
    }

    return 0;
}

void EventPoll::rm_fd(int fd) 
{
    struct epoll_event ev;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
        exit(1);
    }
}

void EventPoll::mod_fd_read(int fd)
{
    struct epoll_event ev;
    // associated file is available for read operations
    // Requests edge-triggered notification for the associated file descriptor.
    // Requests one-shot notification for the associated file descriptor
    // I will rearm it based on state with maybe a new event mask
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    // ev.data.ptr = /**/;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        std::cerr << "Failed to modify fd to read from epoll interest list !" << std::endl;
        exit(1);
    }
}



void EventPoll::mod_fd_write(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
    // ev.data.ptr = /**/;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        std::cerr << "Failed to modify fd to write from epoll interest list !" << std::endl;
        exit(1);
    }
}

void EventPoll::mod_fd_read_ctx(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

void EventPoll::mod_fd_write_ctx(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

void EventPoll::event_loop()
{
    /*
        typedef union epoll_data {
            void    *ptr;           // Pointer to user-defined data 
            int      fd;            // File descriptor
            uint32_t u32;
            uint64_t u64;
        } epoll_data_t;

        struct epoll_event {
            uint32_t     events;     // Epoll events 
            epoll_data_t data;       // User data variable 
        };

        when epoll_wait returns, this array is modified to indicate 
        information about the subset of file descriptors in the 
        interest list that are in the ready state
     */
    struct epoll_event events[MAX_EVENTS]; 

    for(;;) 
    {
        /*
            - waits for I/O events, blocking the calling 
              thread if no events are currently available.
            - can unblock if interrupted by a signal
            - TODO: set timeout, now its blocking forever
        */
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (nfds <= 0) 
        {
            if (errno == EINTR) {
                // interrupted by a signal, try again
                continue;
            }
            // actual error
            throw ServerException(std::string("epoll_wait error : ") +  std::strerror(errno));
        }

        // one or more file descriptors in the interest list became ready
        for(int i = 0; i < nfds; i++)
        {
            if (events[i].data.fd == socket.get_socket()) 
            {
                // handle connection if listener is ready
                handle_new_connections();
            } 
            else 
            {
                req_context *ctx = ((req_context* )events[i].data.ptr);

                if((ctx->state == req_state::DONE) || (events[i].events & (EPOLLHUP | EPOLLERR)))
                {
                    if(ctx->connfd){
                        close(ctx->connfd);
                    }
                    // delete_req_context(c);
                    ctx_pool.free_req_context(ctx);
                }else{
                    handle_client_data(ctx);
                }
            }
        }
    }
}

void EventPoll::handle_new_connections() 
{
    // call accept as many times as we can
    for(;;)
    {
        /*
            A new descriptor is returned by accept 
            for each client that connects to the server. 
        */
        int connfd = socket.accept_connection();
        if(connfd < 0){
            return;
        }

        // apply non-blocking IO to the connection sockets as well
        socket.set_non_blocking(connfd);
        
        // new data structure to hold the context of the IO
        req_context* c = ctx_pool.alloc_req_context(connfd, epoll_fd);

        /*
            - Associated file is available for read operations
            - Requests edge-triggered notification for the associated file descriptor.
            - Requests one-shot notification for the associated file descriptor
            - I will rearm it based on state with maybe a new event mask
        */
        if (register_fd_ctx(c, (EPOLLIN | EPOLLET | EPOLLONESHOT)) < 0) 
        {
            // failed to register client, free memory and try again
            // delete_req_context(c);
            ctx_pool.free_req_context(c);
            close(connfd);
            continue;
        }
    }
}

void EventPoll::handle_client_data(req_context* context) 
{
    if (client_handler_) 
    {
        thread_pool_.QueueJob([this, context]() {
            client_handler_(context);
        });
    }
}