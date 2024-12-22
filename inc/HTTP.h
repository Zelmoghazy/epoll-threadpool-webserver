#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <array>
#include <algorithm>
#include <charconv>
#include <ctime>
#include <cerrno>
#include <unordered_map>
#include <atomic>

#include <sys/types.h>
#include <linux/limits.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include <Application.h>
#include <Utils.h>

#define MAX_REQUEST_SIZE    8192U     // cap it at 8K  
#define CR                  '\r'
#define LF                  '\n'

using namespace std::literals;

enum class http_status_code: uint8_t {
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
};

struct status_code_t{
    int code;
    const char* reason;
};

enum class req_state{
    READING,
    WRITING,
    DONE
};

enum class read_req_status {
    INCOMPLETE = 0,
    COMPLETE = 1,
    ERROR = -1
};

enum class write_req_status {
    INCOMPLETE = 0,
    COMPLETE = 1,
    ERROR = -1
};

struct req_context
{
    req_state           state      = req_state::READING;         
    int                 connfd     = -1;             
    int                 epoll_fd   = -1;           

    /* Reading */
    char                *read_buf  = nullptr;
    char                *read_ptr  = nullptr;
    ssize_t             read_cnt   = 0;
    size_t              total_read = 0;

    /* Writing */
    FILE                *req_file  = nullptr;
    size_t              remaining  = 0; 
};

struct ContextPool
{
    char*              memory_pool;
    std::atomic_size_t bump_index;          // Current allocation index
    void**             free_blocks;         // Array of pointers to free blocks
    std::atomic_int    free_count;          // Number of blocks in free list
    std::atomic_flag   lock;                // Spinlock for thread safety
    size_t             total_blocks;        // Total number of blocks in pool

    static constexpr int POOL_SIZE  =  512;
    static constexpr int BLOCK_SIZE =  (sizeof(req_context) + MAX_REQUEST_SIZE);
    static constexpr int MAX_SPINS  =  100;

    ContextPool();
    ~ContextPool();
    static inline void spin_lock(std::atomic_flag* lock);
    static inline void spin_unlock(std::atomic_flag* lock);
    req_context* alloc_req_context(int connfd, int epollfd);
    void free_req_context(req_context* ctx);
};

extern const std::unordered_map<std::string, std::string> mime_types;

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
    http_status_code parse_request(const char* req);
    http_status_code parse_headers(std::string_view headers_view, size_t& headers_end);
    http_status_code parse_body(std::string_view body_view, size_t body_start);

    static bool is_method_valid(std::string_view method);
    const std::string& get_method() const; 
    const std::string& get_uri() const; 
    const std::string& get_version() const; 
    const std::string& get_body() const; 
    std::string_view get_header(std::string_view name) const; 
    void clear();

};

using RequestHandler = std::function<std::string&(req_context *c)>;

struct http_uri_handler
{
    std::string_view uri;
    std::string_view method;
    RequestHandler handler  = nullptr;
};

class HTTPServer
{
    HTTPParser  parser;
    HTTPBuilder builder;
    std::string root_directory;

    std::vector<http_uri_handler> route_handlers;

public:
    HTTPServer(std::string root_dir = "./Web");
    void setup_default_routes();
    void add_route(const std::string_view method, const std::string_view path, RequestHandler handler);
    bool match_route(const std::string_view uri, const std::string_view method);
    http_uri_handler* find_handler(const std::string_view uri, const std::string_view method);
    std::string& response_static_file(req_context *c, const std::string& uri);
    std::string_view response_body(int status, const std::string& message);
    int send_response_header(req_context *c);
    int write_response(req_context *c , std::string& response);
    enum write_req_status send_response_file(req_context *c);
    std::string& build_error_response(http_status_code code, const std::string& message) ;
    std::string& build_success_response(http_status_code code, const std::string_view file_path, const size_t file_size);
    FILE *get_file_info(const char* filepath, size_t &size);
    static enum read_req_status read_http_request(req_context *c);
};