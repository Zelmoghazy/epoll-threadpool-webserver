#pragma once

#include <cassert>
#include <unistd.h>
#include <array>
#include <string>
#include <sys/types.h>
#include <unordered_map>

#define MAX_REQUEST_SIZE    8192U     // cap it at 8K  

/* 
    - The Status-Code element is a 3-digit integer result code 
      of the attempt to understand and satisfy the request. 
    - The Reason-Phrase is intended to give a short textual 
      description of the Status-Code.
 */
typedef enum StatusCode {
    OK,
    Created,
    Accepted,
    NoContent,
    MovedPermanently,
    MovedTemporarily,
    NotModified,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
}StatusCode;

typedef struct status_code_t{
    int code;
    const char* reason;
}status_code_t;

typedef enum req_state{
    READING,
    WRITING,
    DONE
}req_state;

enum read_req_status {
    READ_REQUEST_INCOMPLETE = 0,
    READ_REQUEST_COMPLETE = 1,
    READ_REQUEST_ERROR = -1
};

enum write_req_status {
    WRITE_REQUEST_INCOMPLETE = 0,
    WRITE_REQUEST_COMPLETE = 1,
    WRITE_REQUEST_ERROR = -1
};

typedef struct req_context
{
    req_state           state;              // current state of the req
    int                 connfd;             // client file descriptor
    int                 epoll_fd;           // epoll file descriptor

    /* Reading */
    char                *read_buf;
    char                *read_ptr;
    ssize_t             read_cnt;
    size_t              total_read;

    /* Writing */
    FILE                *req_file;
    size_t               remaining;
}req_context;

extern const std::unordered_map<std::string, std::string> mime_types;

req_context *new_req_context(int connfd, int epollfd);
void delete_req_context(req_context *c);
ssize_t writen(int fd, const void *vptr, ssize_t n);
ssize_t readn(req_context *c, char *ptr);
