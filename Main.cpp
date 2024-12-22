#include "cJSON.h"

#include "ServerException.h"
#include "Socket.h"
#include "Server.h"
#include "HTTP.h"

// Every thread can have a local copy of this global object
thread_local HTTPServer http_server;

// State machine to handle incoming HTTP request
void handleClient(req_context *c) 
{
    if(c->state == req_state::READING)
    {
        switch (HTTPServer::read_http_request(c))
        {
            case read_req_status::INCOMPLETE:
                c->state = req_state::READING;
                EventPoll::mod_fd_read_ctx(c);
                return;
            case read_req_status::COMPLETE:
                // done reading, send response
                c->state = req_state::WRITING;
                break;
            case read_req_status::ERROR:
                c->state = req_state::DONE;
                // Error, send error response, free memory and end connection
                if(http_server.send_response_header(c)<0){
                    std::cerr << "Error while sending the response header" << std::endl;
                    exit(1);
                }
                // trigger epoll to free allocated memory
                EventPoll::mod_fd_write_ctx(c);
                return;
        }
    }

    if(c->state == req_state::WRITING)
    {
        if(http_server.send_response_header(c)<0){
            // something wrong occurred no idea how to proceed
            std::cerr << "Error while sending the response header" << std::endl;
            exit(1);
        }

        switch (http_server.send_response_file(c))
        {
            case write_req_status::INCOMPLETE:
                c->state = req_state::WRITING;
                EventPoll::mod_fd_write_ctx(c);
                break;

            case write_req_status::COMPLETE:
                c->state = req_state::DONE;                 
                // trigger epoll to free allocated memory
                EventPoll::mod_fd_write_ctx(c);
                break;

            case write_req_status::ERROR:
                c->state = req_state::DONE;
                // trigger epoll to free allocated memory
                EventPoll::mod_fd_write_ctx(c);
                break;
        }
    }
}

void signalHandler(int signum) 
{
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    std::cout << "\nClosing Server......\n";
    exit(0);
}

int main(void) 
{
    signal(SIGINT, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    EventPoll ep("8080", handleClient);
    ep.event_loop();

    return 0;
}