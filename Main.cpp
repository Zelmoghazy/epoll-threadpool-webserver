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
                // rearm to read again (should be thread safe)
                EventPoll::mod_fd_read_ctx(c);
                return;
            case READ_REQUEST_COMPLETE:
                // done reading, send response
                c->state = WRITING;
                break;
            case READ_REQUEST_ERROR:
                c->state = DONE;
                // Error, free memory and end connection
                std::string& error_resp = http_server.build_error_response(InternalServerError, "Internal Server Error");

                http_server.write_response(c, error_resp);
                
                if(c->connfd)
                {
                    close(c->connfd);
                }
                delete_req_context(c);
                return;
        }
    }

    if(c->state == WRITING)
    {
        http_server.send_response_header(c);

        switch (http_server.send_response_file(c))
        {
            case WRITE_REQUEST_INCOMPLETE:
                c->state = WRITING;
                EventPoll::mod_fd_write_ctx(c);
                break;

            case WRITE_REQUEST_COMPLETE:
                c->state = DONE;
                if(c->connfd)
                {
                    close(c->connfd);
                }
                delete_req_context(c);
                break;

            case WRITE_REQUEST_ERROR:
                c->state = DONE;
                if(c->connfd)
                {
                    close(c->connfd);
                }
                delete_req_context(c);
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

    EventPoll ep("8080", handleClient);
    ep.event_loop();

    return 0;
}