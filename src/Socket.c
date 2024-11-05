#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <queue>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <cstring> 
#include <fstream> 

#include <unistd.h>
#include <cstdlib> // For system()
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // for inet_ntoa

class TCPServer {

    struct addrinfo  *res;
    int connfd;
    int listenfd;

    socklen_t cl_addr_len;
    struct sockaddr_storage client_addr;
    char remoteIP[INET6_ADDRSTRLEN];

    TCPServer(const char *ip, const char *port)
    {
        if((listenfd = new_socket(NULL, PORT))<0){
            std::cerr << "Error: couldnt create a socket file descriptor." << std::endl;
            exit(1);
        }
    }
    TCPServer(const char *port)
    {
        TCPServer(nullptr,port);
    }

    ~TCPServer()
    {
        freeaddrinfo(res);
    }

    int new_socket(const char *ip, const char *port)
    {
        struct addrinfo hints, *p;
        int listenfd;
        int yes=1;

        memset(&hints, 0, sizeof(hints));     // Make sure its clean
        hints.ai_family   = AF_UNSPEC;        // use IPv4 or IPv6, whichever
        hints.ai_socktype = SOCK_STREAM;      // TCP
        hints.ai_flags    = AI_PASSIVE;       // fill in my IP for me

        /* Make it protocol independent */
        int err = 0;
        if ((err = getaddrinfo(ip, port, &hints, &res)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
            exit(1);
        }

        for(p = res; p != NULL; p = p->ai_next) 
        {
            // Create a TCP/IP stream socket
            if ((listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
                std::cerr << "Socket creation failed" << std::endl;
                continue;
            }

            // Non-blocking Mode
            int flags = fcntl(listenfd, F_GETFL, 0);
            fcntl(listenfd, F_SETFL, flags|O_NONBLOCK);

            // Prevent the "Address already in use" error message
            if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
                std::cerr << "setsockopt error" << std::endl;
                exit(1);
            }

            // bind the port to the socket
            if (bind(listenfd, res->ai_addr, res->ai_addrlen) == -1) {
                close(listenfd);
                std::cerr << "Binding error" << std::endl;
                continue;
            }
            break;
        }    

        // didnt bind
        if(p == NULL){
            fprintf(stderr,"server: failed to bind\n");
            return -1;
        }

        /* Convert socket to listening socket */
        if (listen(listenfd, BACKLOG) == -1) {
            std::cerr << "Listen failed" << std::endl;
            return -1;
        }
        return listenfd;
    }

    std::string get_ip_address(){
        char ipstr[INET_ADDRSTRLEN];
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        return std::string ip{ipstr}; 
    }

    std::string get_host_name(){
        char name[1024];
        gethostname(name, 1024);
        return std::string ip{name}; 
    }
};