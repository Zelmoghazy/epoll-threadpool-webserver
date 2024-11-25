#include <iostream>

#include <sys/wait.h>

#include "cJSON.h"

#include "ServerException.h"
#include "Socket.h"
#include "Server.h"
#include "HTTP.h"
#include "Parser.h"

// Every thread can have a local copy of this global object
// Supposed to be not shared among them
thread_local HTTPServer http_server;

context_pool *ctx_pool = nullptr;

extern std::unordered_map<std::string, std::string> buttons;

// State machine to handle incoming HTTP request
void handleClient(req_context *c) 
{
    if(c->state == READING)
    {
        switch (HTTPServer::read_http_request(c))
        {
            case READ_REQUEST_INCOMPLETE:
                c->state = READING;
                EventPoll::mod_fd_read_ctx(c);
                return;
            case READ_REQUEST_COMPLETE:
                // done reading, send response
                c->state = WRITING;
                break;
            case READ_REQUEST_ERROR:
                c->state = DONE;

                // Error, send error response, free memory and end connection
                if(http_server.send_response_header(c)<0){
                    std::cerr << "Error while sending the response header" << std::endl;
                    exit(1);
                }
                if(c->connfd){
                    close(c->connfd);
                }
                // delete_req_context(c);
                free_req_context(ctx_pool, c);
                return;
        }
    }

    if(c->state == WRITING)
    {
        if(http_server.send_response_header(c)<0){
            // something wrong occurred no idea how to proceed
            std::cerr << "Error while sending the response header" << std::endl;
            exit(1);
        }

        switch (http_server.send_response_file(c))
        {
            case WRITE_REQUEST_INCOMPLETE:
                c->state = WRITING;
                EventPoll::mod_fd_write_ctx(c);
                break;

            case WRITE_REQUEST_COMPLETE:
                c->state = DONE;
                if(c->connfd){
                    close(c->connfd);
                }
                // delete_req_context(c);
                free_req_context(ctx_pool, c);
                break;

            case WRITE_REQUEST_ERROR:
                c->state = DONE;
                if(c->connfd){
                    close(c->connfd);
                }
                // delete_req_context(c);
                free_req_context(ctx_pool, c);
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

    ctx_pool = create_context_pool();
    assert(ctx_pool);

    EventPoll ep("8080", handleClient);
    ep.event_loop();

    return 0;
}