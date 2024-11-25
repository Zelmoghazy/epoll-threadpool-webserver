#pragma once

#include <cassert>
#include <unistd.h>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <charconv>
#include <ctime>
#include <cerrno>
#include <iostream>
#include <sys/types.h>
#include <unordered_map>
#include <linux/limits.h>
#include <sys/sendfile.h>
#include <Parser.h>
#include <Utils.h>

#define MAX_REQUEST_SIZE    8192U     // cap it at 8K  
#define CR                  '\r'
#define LF                  '\n'

using namespace std::literals;

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

#define POOL_SIZE 1024 
#define BLOCK_SIZE (sizeof(req_context) + MAX_REQUEST_SIZE)
#define MAX_SPINS 1000 

typedef struct context_pool{
    char* memory_pool;
    std::atomic_size_t bump_index;  // Current allocation index
    void** free_blocks;        // Array of pointers to free blocks
    std::atomic_int free_count;     // Number of blocks in free list
    std::atomic_flag lock;          // Spinlock for thread safety
    size_t total_blocks;       // Total number of blocks in pool
} context_pool;

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

/* 
struct context_pool
{
    char* memory_pool;
    size_t bump_index;          // Current allocation index
    void** free_blocks;         // Array of pointers to free blocks
    int free_count;             // Number of blocks in free list
    size_t total_blocks;        // Total number of blocks in pool

    static constexpr int POOL_SIZE  =   128;
    static constexpr int BLOCK_SIZE =  (sizeof(req_context) + MAX_REQUEST_SIZE);

    context_pool();
    ~context_pool();
    req_context* alloc_req_context(int connfd, int epollfd);
    void free_req_context(req_context* ctx);
};
*/

extern const std::unordered_map<std::string, std::string> mime_types;

static inline void spin_lock(std::atomic_flag* lock);
static inline void spin_unlock(std::atomic_flag* lock);
context_pool* create_context_pool(void);
void destroy_context_pool(context_pool* pool);
req_context* alloc_req_context(context_pool* pool, int connfd, int epollfd);
void free_req_context(context_pool* pool, req_context* ctx); 

req_context *new_req_context(int connfd, int epollfd);
void delete_req_context(req_context *c);
ssize_t writen(int fd, const void *vptr, ssize_t n);
ssize_t readn(req_context *c, char *ptr);


/* 
    Very simple class to easily build HTTP responses
    Not necessarily needed but I wanted to try method chaining 
*/
class HTTPBuilder 
{
private:
    int status_code = 0;
    std::string response;

    std::string body;
    std::string body_size;

    std::string date;
    std::string ext;

    std::string headers;
public:
    HTTPBuilder(); 
    HTTPBuilder& http_resp_add_status(int idx);
    HTTPBuilder& http_resp_add_content_body(std::string_view content); 
    HTTPBuilder& http_resp_add_content_length(size_t size); 
    HTTPBuilder& http_resp_add_content_type(std::string_view type); 
    std::string_view http_get_content_type(std::string_view file_path);
    HTTPBuilder& http_resp_add_content_encoding(std::string_view encoding);
    HTTPBuilder& http_resp_add_allow(std::string_view methods); 
    HTTPBuilder& http_resp_add_authorization(std::string_view auth);
    HTTPBuilder& http_resp_add_date(); 
    HTTPBuilder& http_resp_add_expires(std::string_view expires);
    HTTPBuilder& http_resp_add_from(std::string_view email);
    HTTPBuilder& http_resp_add_if_modified_since(std::string_view date);
    HTTPBuilder& http_resp_add_last_modified(std::string_view last_modified);
    HTTPBuilder& http_resp_add_location(std::string_view location);
    HTTPBuilder& http_resp_add_pragma(std::string_view directive);
    HTTPBuilder& http_resp_add_referer(std::string_view referer);
    HTTPBuilder& http_resp_add_server(std::string_view server_name);
    HTTPBuilder& http_resp_add_user_agent(std::string_view user_agent);
    HTTPBuilder& http_resp_add_www_auth(std::string_view auth);
    HTTPBuilder& http_resp_add_access_auth(std::string_view access_auth);
    HTTPBuilder& http_resp_add_custom_header(std::string_view key, std::string_view value);
    std::string& build();
    void clear();
};

/*
    To parse the incoming request header
*/
class HTTPParser 
{
private:
    std::string method;
    std::string uri;
    std::string version;

    /* Maybe do something with them later */
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    size_t header_count = 0;

    std::string body;

public:
    HTTPParser();
    StatusCode parse_request(const char* req);
    StatusCode parse_headers(std::string_view headers_view, size_t& headers_end);
    StatusCode parse_body(std::string_view body_view, size_t body_start);

    static bool is_method_valid(std::string_view method);
    const std::string& get_method() const; 
    const std::string& get_uri() const; 
    const std::string& get_version() const; 
    const std::string& get_body() const; 
    std::string_view get_header(std::string_view name) const; 
    void clear();

};

class HTTPServer
{
    HTTPParser  parser;
    HTTPBuilder builder;
    std::string root_directory;

    using RequestHandler = std::function<std::string&(req_context *c)>;
    std::unordered_map<std::string, std::unordered_map<std::string, RequestHandler>> route_handlers;

public:
    HTTPServer(std::string root_dir = "./Web");
    void setup_default_routes();
    void add_route(const std::string& method, const std::string& path, RequestHandler handler);
    std::string& response_static_file(req_context *c, const std::string& uri);
    std::string_view response_body(int status, const std::string& message);
    int send_response_header(req_context *c);
    int write_response(req_context *c , std::string& response);
    enum write_req_status send_response_file(req_context *c);
    std::string& build_error_response(int status, const std::string& message) ;
    std::string& build_success_response(int status, const std::string_view file_path, const size_t file_size);
    FILE *get_file_info(const char* filepath, size_t &size);
    static enum read_req_status read_http_request(req_context *c);
};