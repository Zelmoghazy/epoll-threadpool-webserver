#pragma once

#include <unistd.h> 
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>

#include <cerrno>
#include <cstring>

#include <iostream>
#include <string>

#include <sys/socket.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>

struct Socket
{
    int sockfd;
    static constexpr int BACKLOG = SOMAXCONN; // how many pending connections queue will hold

    std::string port;

    Socket();
    ~Socket();

    /* 
        Delete copy constructor and assignment operator  
        dont want multiple objects refering to the same sockfd
    */
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Move constructors
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    
    void tcp_socket(const char *ip, const char* port);
    void wait_connection();
    int accept_connection();
    int get_socket() const; 

    std::string get_host_ip_addr();
    std::string get_host_name();
    std::string get_ip_addr(struct sockaddr *sa);

    void set_non_blocking(int fd);
    void set_opt_reuse_addr(bool on = true);
    void set_opt_keep_alive(bool on = true); 
    void set_opt_tcp_no_delay(bool on = true); 
    void set_opt_tcp_quick_ack(bool on = true);
    void set_opt_tcp_fast_open(bool len);
    void set_opt_linger();
    void set_opt_rcvbuf(int bufsize);
    void set_opt_sndbuf(int bufsize); 
};