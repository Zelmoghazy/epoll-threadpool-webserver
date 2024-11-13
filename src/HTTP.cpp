#include <HTTP.h>



status_code_t codes[] = 
{
    /*  2xx: Success - The action was successfully received, understood, and accepted. */
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {204, "No Content"},

    /*  3xx: Redirection - Further action must be taken in order to complete the request */
    {301, "Moved Permanently"},
    {302, "Moved Temporarily"},
    {304, "Not Modified"},

    /* 4xx: Client Error - The request contains bad syntax or cannot be fulfilled */
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {403, "Forbidden"},
    {404, "Not Found"},

    /* 5xx: Server Error - The server failed to fulfill an apparently valid request */
    {500, "Internal Server Error"},
    {501, "Not Implemented"},         // if the method is unrecognized or not implemented
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
};

// https://www.iana.org/assignments/media-types/media-types.xhtml#example
const std::unordered_map<std::string, std::string> mime_types = 
{
    {"json", "application/json"},
    {"pdf", "application/pdf"},
    {"ttf", "font/ttf"},
    {"woff", "font/woff"},
    {"gif", "image/gif"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"png", "image/png"},
    {"webp", "image/webp"},
    {"svg", "image/svg+xml"},
    {"ico", "image/vnd.microsoft.icon"},
    {"csv", "text/csv"},
    {"html", "text/html"},
    {"css", "text/css"},
    {"js", "text/javascript"},
    {"md", "text/markdown"},
    {"txt", "text/plain"},
    {"mp4", "video/mp4"},
};

/* Valid HTTP Methods */
constexpr std::array<std::string_view, 9> valid_methods =
{
    "GET", "POST", "PUT", "DELETE", "HEAD", 
    "OPTIONS", "PATCH", "TRACE", "CONNECT"
};



/* didnt want to make it a whole class */
req_context *new_req_context(int connfd, int epollfd)
{
    req_context *c = new req_context;

    c->state      = READING;
    c->connfd     = connfd;
    c->epoll_fd   = epollfd;

    c->read_buf = new char[MAX_REQUEST_SIZE];
    c->read_ptr = nullptr;
    c->read_cnt = 0;
    c->total_read = 0;

    c->req_file = nullptr;
    c->remaining = 0;

    return c;
}

void delete_req_context(req_context *c)
{
    if (c)
    {
        delete[] c->read_buf;
        if (c->req_file) {
            fclose(c->req_file);
            c->req_file = nullptr;
        }
        delete c;
    }
}


/* From W. Richard Stevens - UNIX Network Programming */
/* Write may actually write less than expected for various reasons (interrupts, ..) */
ssize_t writen(int fd, const void *vptr, ssize_t n)  /* Write "n" bytes to a descriptor. */
{
    assert(n>0);
    
    size_t      nleft;
    ssize_t     nwritten;
    const char  *ptr;

    ptr = (char *)vptr;
    nleft = (size_t)n;

    // loop until all bytes are written
    while (nleft > 0) {
        if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
            // Interrupt occurred , just try again
            if (nwritten < 0 && errno == EINTR){
                nwritten = 0;       /* and call write() again */
            }
            else
            {
                // actual error
                return(-1);         /* error */
            }
        }

        // nwritten should be positive
        nleft -= (size_t)nwritten;
        ptr   += nwritten;
    }
    return(n);
}

/* data is read into a buffer (read_buf) in chunks and then supplied to the caller one byte at a time */
ssize_t readn(req_context *c, char *ptr)
{
    // check if the buffer still contains data
    if (c->read_cnt <= 0) {
again:
        // read as much as you can
        if ((c->read_cnt = read(c->connfd, (c->read_buf + c->total_read), MAX_REQUEST_SIZE - c->total_read)) < 0) {
            if (errno == EINTR){
                // interrupted, try again
                goto again;
            }
            // error occurred
            c->read_buf[0] = '\0';
            return(-1);
        } 
        else if (c->read_cnt == 0)
        {
            // end-of-file
            c->read_buf[0] = '\0';
            return(0);
        }
        // read_cnt should be positive
        c->read_ptr     = c->read_buf;
        c->total_read  += (size_t)c->read_cnt;
        c->read_buf[c->total_read] = '\0';
    }

    // buffer still contains data, return one byte at a time using *ptr
    c->read_cnt--;
    *ptr = *c->read_ptr++;
    // read successfully
    return(1);
}
