#include <Socket.h>
#include <ServerException.h>

Socket::Socket(): sockfd(-1){
    port.reserve(64);
}

Socket::~Socket()
{
    if (sockfd != -1) {
        close(sockfd);
    }
}

Socket::Socket(Socket&& other) noexcept : sockfd(other.sockfd) 
{
    other.sockfd = -1;
}

Socket& Socket::operator=(Socket&& other) noexcept 
{
    if (this != &other) 
    {
        if (sockfd != -1) {
            close(sockfd);
        }
        sockfd = other.sockfd;
        other.sockfd = -1;
    }
    return *this;
}

void Socket::tcp_socket(const char *ip, const char* port)
{
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(hints));     // Make sure its clean
    hints.ai_family   = AF_UNSPEC;        // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;      // TCP
    hints.ai_flags    = AI_PASSIVE;       // fill in my IP for me

    int err;
    /* Make it protocol independent */
    if ((err = getaddrinfo(ip, port, &hints, &res)) < 0) {
        throw ServerException(std::string("getaddrinfo error: ") + gai_strerror(err));
    }

    std::string last_error;

    /*
        the linked list may have more than one addrinfo structure
        the application should try using the addresses in the order
        in which they are returned until we successfully bind
    */
    for(p = res; p != NULL; p = p->ai_next) 
    {
        // Create a TCP/IP stream socket
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            last_error = std::string("Socket creation failed: ") + std::strerror(errno);
            continue;
        }

        // Non-blocking IO
        set_non_blocking(sockfd);

        // Prevent the "Address already in use" error message
        set_opt_reuse_addr();

        // bind the port to the socket
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            last_error = std::string("Binding failed: ") + std::strerror(errno);
            close(sockfd);
            continue;
        }
        break;
    }    

    // not needed anymore
    freeaddrinfo(res);

    // didnt bind
    if(p == NULL){
        throw ServerException("Failed to bind to any address. Last error: " + last_error);
    }

    this->port += port;
}

void Socket::wait_connection()
{
    /* Convert socket to listening socket */
    if (listen(sockfd, BACKLOG) < 0) {          
        close(sockfd);
        throw ServerException(std::string("Listen failed: ") +  std::strerror(errno));
    }

    std::cout << "Server listening on " << get_host_name() <<  " http://" << get_host_ip_addr() << ':' << port << std::endl;
}

int Socket::accept_connection()
{
    int connfd;
    struct sockaddr_storage client_addr;
    socklen_t cl_addr_len = sizeof(client_addr);

    /*  A new descriptor is returned by accept for each client that connects to the server. */
    if ((connfd = accept(sockfd, (struct sockaddr *)&client_addr, &cl_addr_len)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Accept error : " << std::strerror(errno);
        }
        return -1;
    }

    std::cout << "Client connected from IP: " << get_ip_addr((struct sockaddr *)&client_addr) << std::endl;

    return connfd;
}

int Socket::get_socket() const 
{
    return sockfd;
}

std::string Socket::get_host_ip_addr() 
{
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;
    void *tmpAddrPtr = nullptr;
    std::string ipAddress = "No IP address found";

    if (getifaddrs(&ifAddrStruct) == -1) {
        perror("getifaddrs");
        return "Error getting network interfaces";
    }

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == nullptr) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) 
        {
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

            // Skip the loopback address and take the first non-loopback IPv4 address
            if (strcmp(addressBuffer, "127.0.0.1") != 0) {
                ipAddress = addressBuffer;
                break;
            }
        }
    }

    if (ifAddrStruct != nullptr) {
        freeifaddrs(ifAddrStruct);
    }

    return ipAddress;
}

std::string Socket::get_host_name() 
{
    char hostname[256]; // Buffer to store the hostname
    
    // Call get_host_name to get the name of the host
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        perror("get_host_name");
        return "Error getting hostname";
    }
    
    return std::string(hostname); // Convert to std::string
}

std::string Socket::get_ip_addr(struct sockaddr *sa) 
{
    char ipstr[INET6_ADDRSTRLEN]; 
    void *addr = nullptr;

    /* Protocol Independent */
    switch (sa->sa_family) 
    {
        case AF_INET: { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)sa;
            addr = &(ipv4->sin_addr);
            break;
        }
        case AF_INET6: { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sa;
            addr = &(ipv6->sin6_addr);
            break;
        }
        default:
            return "Unknown AF"; // Address family not handled
    }
    // Convert address to a string and store it in ipstr
    inet_ntop(sa->sa_family, addr, ipstr, sizeof(ipstr));
    return std::string(ipstr);
}

void Socket::set_non_blocking(int fd)
{
    /* 
        - file control : set socket for nonblocking I/O
          beware not to clear all the other file status flags.  
        - I/O system calls that would block now will return -1
          and errno will be set to EWOULDBLOCK or EAGAIN
    */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags|O_NONBLOCK);
}

void Socket::set_opt_reuse_addr(bool on)
{
    // Prevent the "Address already in use" error message
    int optval = on ? 1:0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

void Socket::set_opt_keep_alive(bool on) 
{
    int optval = on ? 1 : 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval,sizeof(optval)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

// Disable Nagle's Algorithm
void Socket::set_opt_tcp_no_delay(bool on) 
{
    int optval = on ? 1 : 0;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval,sizeof(optval)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

// allows data to be sent in the SYN packet, speeding up 
// connection setup for subsequent connections to the same server.
void Socket::set_opt_tcp_fast_open(bool len)
{
    int qlen = len;  
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}    

void Socket::set_opt_tcp_quick_ack(bool on)
{
    int quickack = on ? 1 : 0;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

void Socket::set_opt_linger()
{
    struct linger linger_opt = {1, 10};  // Enable linger with a 10-second timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

void Socket::set_opt_rcvbuf(int bufsize) 
{
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}

void Socket::set_opt_sndbuf(int bufsize) 
{
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        std::cerr << "setsockopt error : " << __func__ << strerror(errno) << std::endl;
    }
}
