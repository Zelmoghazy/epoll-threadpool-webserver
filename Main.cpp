#include <cerrno>
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
#include <ctime>

#include <unistd.h>
#include <cstdlib> 
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
#include <arpa/inet.h>  

#include "cJSON.h"

#include "Parser.h"

#define PORT        "8080"    // the port users will be connecting to
#define BACKLOG     10        // how many pending connections queue will hold

char buffer[1024] = {0};



std::string read_entire_file(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file: " << filePath << std::endl;
        return "";
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

std::string hashmapToJSON(std::unordered_map<std::string, std::string>& buttons) 
{
    cJSON *root = cJSON_CreateObject();
    cJSON *buttonArray = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "buttons", buttonArray);

    for (const auto &pair : buttons) {
        cJSON *button = cJSON_CreateObject();
        cJSON_AddStringToObject(button, "label", pair.first.c_str());
        cJSON_AddStringToObject(button, "action", pair.second.c_str());
        cJSON_AddItemToArray(buttonArray, button);
    }

    char *jsonString = cJSON_Print(root);
    std::string result(jsonString);
    cJSON_Delete(root);
    free(jsonString);

    return result;
}

void appendToFile(const std::string& label, const std::string& action, const std::string& filename) 
{
    std::ofstream outFile;
    
    // Open the file in append mode
    outFile.open(filename, std::ios::app); 
    if (!outFile) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    // Write the label and action in the format "label:action"
    outFile << label << ":" << action << std::endl;

    // Close the file
    outFile.close();
}

/* 
    The Status-Code element is a 3-digit integer result code of the
    attempt to understand and satisfy the request. The Reason-Phrase is
    intended to give a short textual description of the Status-Code.
 */
typedef enum StatusCode {
    OK ,
    Created ,
    Accepted ,
    NoContent ,
    MovedPermanently,
    MovedTemporarily,
    NotModified ,
    BadRequest ,
    Unauthorized ,
    Forbidden ,
    NotFound ,
    InternalServerError ,
    NotImplemented ,
    BadGateway ,
    ServiceUnavailable ,
}StatusCode;

typedef struct status_code{
    int code;
    const char* reason;
}status_code;

status_code codes[] = {
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

static constexpr std::array<std::string_view, 9> VALID_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", 
    "OPTIONS", "PATCH", "TRACE", "CONNECT"
};

/* 
    Very simple class to easily build HTTP responses
    I wanted to try method chaining 
*/
class HTTPBuilder 
{
private:
    int status_code = 0;
    std::string response;

    std::string body;
    std::string body_size;

    std::string date;
    std::string extension;

    std::unordered_map<std::string_view, std::string_view> headers;

public:
    HTTPBuilder() {
        response.reserve(4096); 

        body.reserve(1024);
        body_size.reserve(16);

        date.reserve(64);
        extension.reserve(16);
    }

    HTTPBuilder& http_resp_add_status(StatusCode idx) 
    {
        status_code = idx;
        return *this;
    }

    HTTPBuilder& http_resp_add_content_body(std::string_view content) 
    {
        body.clear();
        body += content;
        http_resp_add_content_length(body.size());
        return *this;
    }

    HTTPBuilder& http_resp_add_content_length(size_t size) 
    {
        body_size.clear();
        body_size += std::to_string(size);
        headers["Content-Length"] = std::string_view(body_size);
        return *this;
    }

    HTTPBuilder& http_resp_add_content_type(std::string_view type) 
    {
        headers["Content-Type"] = type;
        return *this;
    }

    std::string http_get_content_type(std::string_view file_path) 
    {
        ext.clear();
        auto pos = file_path.find_last_of('.');
        if (pos != std::string::npos) {
            ext += file_path.substr(pos + 1);
            auto it = mime_types.find(ext);
            if (it != mime_types.end()) {
                return it->second;  
            }
        }
        return "application/octet-stream";
    }

    HTTPBuilder& http_resp_add_content_encoding(std::string_view encoding) 
    {
        headers["Content-Encoding"] = encoding;
        return *this;
    }

    HTTPBuilder& http_resp_add_allow(std::string_view methods) 
    {
        headers["Allow"] = methods;
        return *this;
    }

    HTTPBuilder& http_resp_add_authorization(std::string_view auth) 
    {
        headers["Authorization"] = auth;
        return *this;
    }

    /*
        Preferred as an Internet standard and represents
        a fixed-length subset of that defined by RFC 1123
    */
    HTTPBuilder& http_resp_add_date() 
    {
        date.clear();
        std::time_t now = std::time(nullptr);
        char buf[100];
        if (std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now))) 
        {
            date += buf;
            headers["Date"] = std::string_view(date)
        }
        return *this;
    }

    HTTPBuilder& http_resp_add_expires(std::string_view expires)
    {
        headers["Expires"] = expires;
        return *this;
    }

    HTTPBuilder& http_resp_add_last_modified(std::string_view last_modified) 
    {
        headers["Last-Modified"] = last_modified;
        return *this;
    }

    HTTPBuilder& http_resp_add_location(std::string_view location) 
    {
        headers["Location"] = location;
        return *this;
    }

    HTTPBuilder& http_resp_add_referer(std::string_view referer) 
    {
        headers["Referer"] = referer;
        return *this;
    }

    HTTPBuilder& http_resp_add_server(std::string_view server_name) 
    {
        headers["Server"] = server_name;
        return *this;
    }

    HTTPBuilder& http_resp_add_user_agent(std::string_view user_agent) 
    {
        headers["User-Agent"] = user_agent;
        return *this;
    }

    HTTPBuilder& http_resp_add_www_auth(std::string_view auth) 
    {
        headers["WWW-Authenticate"] = auth;
        return *this;
    }

    HTTPBuilder& http_resp_add_access_auth(std::string_view access_auth) 
    {
        headers["Access-Control-Allow-Origin"] = access_auth;
        return *this;
    }

    HTTPBuilder& http_resp_add_custom_header(std::string_view key, std::string_view value) 
    {
        headers[key] = value;
        return *this;
    }


    /*
        Finally build the constructed response header
    */
    std::string build() const 
    {
        response.clear();

        // status line
        response += "HTTP/1.0 ";
        response += std::to_string(codes[status_code].code);
        response += " ";
        response += codes[status_code].reason;
        response += "\r\n";

        // headers
        for (const auto& header : headers) {
            response += header.first + ": " + header.second + "\r\n";
        }

        headers.clear();

        // body if added
        response += "\r\n";
        response += body;

        return response;
    }
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
    std::unordered_map<std::string, std::string> headers;

public:

    HTTPParser(){
        method.reserve(16);
        uri.reserve(128);
        version.reserve(16);
    }
    /*
        A request message from a client to a server includes, within the
        first line of that message :
            1- the method to be applied to the resource
            2- the identifier of the resource
            3- the protocol version in use.
     */
    StatusCode parse_request(const char* req) 
    {
        // clear first
        clear();

        std::string_view request(req);  // no copying (I think ?)

        /* ------------------ Request line ------------------ */ 
        auto end_of_line = request.find("\r\n");
        if (end_of_line == std::string_view::npos) {
            return BadRequest; 
        }

        std::string_view request_line = request.substr(0, end_of_line);

        // Extract method
        auto first_space = request_line.find(' ');
        if (first_space == std::string_view::npos){
            return BadRequest; 
        } 
        method += std::string(request_line.substr(0, first_space));
        if(!is_method_valid(method))
        {
            return BadRequest;
        }

        // Extract URI
        auto second_space = request_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos) {
            return BadRequest; 
        }
        uri += std::string(request_line.substr(first_space + 1, second_space - first_space - 1));

        // Extract version
        version += std::string(request_line.substr(second_space + 1));

        if (version.substr(0, 5) != "HTTP/") {
            return BadRequest; 
        }

        if (version != "HTTP/1.0" && version != "HTTP/1.1") {
            return InternalServerError;  
        }
        // Parse rest of headers
        if (!parseHeaders(request.substr(end_of_line + 2))) {
            return BadRequest;  
        }

        return OK;  
    }

    StatusCode parseHeaders(std::string_view headers_view) 
    {
        size_t pos = 0;

        while (pos < headers_view.size()) 
        {
            // Find end of the current line
            auto end_of_line = headers_view.find("\r\n", pos);
            if (end_of_line == std::string_view::npos){
                return BadRequest; 
            } 

            // Get the header line
            std::string_view line = headers_view.substr(pos, end_of_line - pos);
            pos = end_of_line + 2;

            if (line.empty()) {
               // we are done
               return OK; 
            }

            auto colon_pos = line.find(':');
            if (colon_pos == std::string_view::npos){
                // skip malformed headers
                continue; 
            } 

            std::string header_name = std::string(line.substr(0, colon_pos));
            std::string_view header_value_view = line.substr(colon_pos + 1);

            // Trim whitespace from header value
            header_value_view.remove_prefix(std::min(header_value_view.find_first_not_of(" \t"), header_value_view.size()));
            header_value_view.remove_suffix(header_value_view.size() - header_value_view.find_last_not_of(" \t") - 1);

            headers[std::move(header_name)] = std::string(header_value_view);
        }
    }

    static bool is_method_valid(std::string_view method) 
    {
        return std::find(VALID_METHODS.begin(), VALID_METHODS.end(), method) != VALID_METHODS.end();
    }

    // Getters
    const std::string& get_method() const 
    { 
        return method; 
    }

    const std::string& get_uri() const 
    { 
        return uri; 
    }

    const std::string& get_version() const 
    {
        return version; 
    }

    const std::unordered_map<std::string, std::string>& get_headers() const 
    { 
        return headers; 
    }
    
    // Get specific header value
    std::string get_header(const std::string& key) const 
    {
        auto it = headers.find(key);
        return (it != headers.end()) ? it->second : "";
    }

    // Clear all parsed data
    void clear() 
    {
        method.clear();
        uri.clear();
        version.clear();
        headers.clear();
    }
};


class HTTPServer
{
    HTTPParser  parser;
    HTTPBuilder builder;
    std::string root_directory;

    using RequestHandler = std::function<std::string(const HTTPParser&)>;
    
    std::unordered_map<std::string, std::unordered_map<std::string, RequestHandler>> route_handlers;


    HTTPServer(const std::string& root_dir = "./www")
    {
        char absolute_path[PATH_MAX]; 
        if(!realpath(root_dir.cstr(), resolved_path)){
            std::cerr << "root path error" << std::endl;
            exit(1);
        }

        root_directory.assign(absolute_path, PATH_MAX);
        setup_default_routes();
    }

    void setup_default_routes() 
    {
        add_route("GET", "/", [this](const HTTPParser& parser) {
            return serve_file("index.html");
        });

        add_route("GET", "/about", [this](const HTTPParser& parser) {
            return serve_file("about.html");
        });

        // POST handlers
        add_route("POST", "/submit", [this](const HTTPParser& parser) {
            return handle_form_submission(parser);
        });
    }

    void add_route(const std::string& method, const std::string& path, RequestHandler handler) 
    {
        route_handlers[method][path] = handler;
    }

    void send_response_header(req_context *c)
    {
        std::string_view response;

        switch(parser.parse_request(c->read_buf))
        {
            case OK:
                std::string_view method = parser.get_method();
                std::string_view uri    = parser.get_uri();

                /*
                    - Many operating systems use ".." as a path component to indicate a
                      directory level above the current one

                    - an HTTP server must disallow any such construct in the Request-URI if it
                      would otherwise allow access to a resource outside those intended to
                      be accessible via the HTTP server.
                */
                if (uri.find("..") != std::string::npos) {
                    response = build_error_response(BAD_REQUEST, "Invalid path");
                }

                if (route_handlers.find(method) == route_handlers.end()) {
                    response = build_error_response(METHOD_NOT_ALLOWED, "Method not allowed");
                    break;
                }

                // Check if route exists for this method
                auto& method_routes = route_handlers[method];

                // else we will serve a static file 
                if (method_routes.find(uri) == method_routes.end()) 
                {
                    if (method == "GET") 
                    {
                        std::string file_path = root_directory + "/" + filename;

                        // Do one more check to make sure everything is fine
                        if(!file_path_check(file_path)){
                            response = build_error_response(BAD_REQUEST, "Invalid path");
                            break;
                        }

                        size_t file_size;

                        FILE *file = get_file_info(file_path, file_size);

                        if(!file){
                            response = build_error_response(NOT_FOUND, "Resource not found");
                        }

                        c->file = file;
                        c->remaining = file_size;

                        response = build_success_response(OK,"Sending Response header", file_path, file_size);
                    }
                    break;
                }

                break;
            
            case BadRequest:
                response = build_error_response(BAD_REQUEST, "Bad Request");
                break;
            
            case InternalServerError:
                response = build_error_response(INTERNAL_SERVER_ERROR, "Internal Server Error");
                break;
            
            default:
                std::cout << "500 Internal Server Error: Unexpected parsing error.\n";
                break;
        }

        write_response(c,response);

    }

    void write_response(req_context *c , std::string_view response)
    {
        if(writen(c->connfd, response.c_str(),response.size())<0){
            std:cerr << "Error while sending the response header" << std::endl;
        }
    }

    int send_response_file(req_context *c)
    {
        FILE *file = c->file;
        int filefd = fileno(file);
        size_t left = status->remaining;

        size_t readn;


        ssize_t left = file_size;
        ssize_t writen;

        while (left > 0) 
        {
            writen = sendfile(connfd, filefd, NULL, left);
            if (writen < 0) 
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    return -1;
                }
            } else if (writen == 0) {
                return -1;
            } else {
                left -= writen;
            }

            if (left == 0) {
                status->req_status = Ended;
            } else {
                status->left = left;
            }
        }
    }

    bool file_path_check(const std::string& file_path) 
    {
        char abs_path[PATH_MAX];

        if (realpath(file_path.c_str(), abs_path) == nullptr) {
            return false;
        }

        if (strncmp(root_directory.c_str(), abs_path, root_directory.length()) != 0) {
            return false;
        }

        return true;
    }

    std::string build_error_response(int status, const std::string& message) 
    {
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type("text/html")
            .http_resp_add_content_body(
                "<html><body><h1>Error " + std::to_string(status) + "</h1>"
                "<p>" + message + "</p></body></html>")
            .build();
    }

    std::string build_success_response(int status, const std::string& message, const std::string& file_path, const size_t file_size) 
    { 
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type(builder.get_content_type(file_path))
            .http_resp_add_content_length()
            .build();
    }

    FILE *get_file_info(const std::string& filepath, size_t &size) 
    {
        FILE *file = fopen(file_path.cstr(), "rb");

        if(!file){
            return NULL;
        }

        fseek(file, 0L, SEEK_END);
        size = ftell(file);
        fseek(file, 0L, SEEK_SET);

        return file;
    }
}

// Every thread can have a local copy of this global object
// Supposed to be not shared among them
thread_local HTTPServer http_server;

class ThreadPool 
{
public:
    ThreadPool();
    ~ThreadPool();
    void QueueJob(const std::function<void()>& job);
    bool busy();

private:
    void ThreadLoop();

    bool should_terminate = false;           // Tells threads to stop looking for jobs
    std::mutex queue_mutex;                  // Prevents data races to the job queue
    std::condition_variable mutex_condition; // Allows threads to wait on new jobs or termination 
    std::vector<std::thread> threads;
    std::queue<std::function<void()>> jobs;
};


ThreadPool::ThreadPool() 
{
    // get as much threads as cpu cores
    const uint32_t num_threads = std::thread::hardware_concurrency(); 
    std::cout<< "number of threads created = " << num_threads << std::endl; 

    for (uint32_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(std::thread(&ThreadPool::ThreadLoop,this));
    }
}

ThreadPool::~ThreadPool() 
{
    std::unique_lock<std::mutex> lock(queue_mutex);

    should_terminate = true;

    lock.unlock();

    /* Join all the running threads */
    mutex_condition.notify_all();
    for (std::thread& active_thread : threads) {
        active_thread.join();
    }
    threads.clear();
}

void ThreadPool::ThreadLoop() 
{
    while (true) 
    {
        std::function<void()> job;
        
        std::unique_lock<std::mutex> lock(queue_mutex);

        mutex_condition.wait(lock, [this] {
            return (!jobs.empty() || should_terminate);
        });

        if (should_terminate) {
            return;
        }

        job = jobs.front();     // get task from task list
        jobs.pop();             // remove the task from the list because we are going to execute it

        lock.unlock();

        job();                 // Execute the task
    }
}

void ThreadPool::QueueJob(const std::function<void()>& job) 
{
    std::unique_lock<std::mutex> lock(queue_mutex);

    jobs.push(job);
    
    lock.unlock();

    mutex_condition.notify_one();
}

bool ThreadPool::busy() 
{
    bool poolbusy;
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        poolbusy = !jobs.empty();
    }
    return poolbusy;
}

std::unordered_map<std::string, std::string> buttons;


void executeCommand(const std::string& command) 
{
    // will handle piping output later
    pid_t pid = fork();
    
    if (pid < 0) {
        std::cerr << "Fork failed: " << std::strerror(errno) << std::endl;
        return;
    }
    else if (pid == 0) 
    {  
        while(1);
        execl("/bin/sh", "sh", "-c", command.c_str(), (char*)nullptr);
        
        // If execl fails
        std::cerr << "Failed to execute: " << std::strerror(errno) << std::endl;
        exit(1);
    }
    else
    {
        // Parent process
        int status;
        pid_t result = waitpid(pid, &status, 0);

        if (result == -1) {
            std::cerr << "waitpid failed" << std::endl;
            return;
        }

        if (WIFEXITED(status)) {
            std::cout << "Child process exited with status: " << WEXITSTATUS(status) << std::endl;
        } else if (WIFSIGNALED(status)) {
            std::cout << "Child process terminated by signal: " << WTERMSIG(status) << std::endl;
        }
    }
}

/* From W. Richard Stevens - UNIX Network Programming */
ssize_t readn(int fd, void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;

    ptr = vptr;
    nleft = n ;

    while(nleft > 0){
        if ((nread = read (fd, ptr, nleft)) < 0) 
        {
            if (errno == EINTR)
            {
                nread = 0;  // call read again
            }
            else
            {
                return (-1);
            }
        } 
        else if (nread == 0)
        {
            break;          // reached EOF
        }
        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft);
}

/* Write may actually write less than expected for various reasons (interrupts, ..) */
ssize_t                     /* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
    size_t      nleft;
    ssize_t     nwritten;
    const char  *ptr;

    ptr = vptr;
    nleft = n;

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

        nleft -= nwritten;
        ptr   += nwritten;
    }
    return(n);
}

enum class req_state{
    READING,
    WRITING,
    DONE
}req_state;

#define MAX_REQ     21148

struct req_context
{
    req_state           state;              // current state of the req
    int                 connfd;             // client file descriptor
    int                 epoll_fd;             // epoll file descriptor

    /* Reading */
    char                *read_buf;
    char                *read_ptr;
    int                 read_cnt;
    int                 total_read;

    /* Writing */
    FILE                *req_file;
    int                 remaining;
}req_context;

req_context *new_req_context(int connfd, int epollfd)
{
    req_context *c = new req_context;

    c->connfd   = connfd;
    c->epollf   = epollfd;

    c->read_buf = new char[MAX_REQ];
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
        }
        delete c;
    }
}

/* data is read into a buffer (read_buf) in chunks and then supplied to the caller one byte at a time */
static ssize_t
my_read(req_context *c, char *ptr)
{
    // check if the buffer still contains data
    if (c->read_cnt <= 0) {
again:
        // all bytes are read, read more from the file
        if ((c->read_cnt = read(c->connfd, c->read_buf + c->total_read, sizeof(c->read_buf)-c->total_read)) < 0) {
            if (errno == EINTR){
                // interrupted, try again
                goto again;
            }
            // error occurred
            return(-1);
        } 
        else if (c->read_cnt == 0)
        {
            // end-of-file
            return(0);
        }
        c->read_ptr = c->read_buf;
        c->total_read  += c->read_cnt;
    }

    // buffer still contains data, return one byte at a time using *ptr
    c->read_cnt--;
    *ptr = *c->read_ptr++;
    // read successfully
    return(1);
}

#define MAX_REQUEST_SIZE 8192
#define CR '\r'
#define LF '\n'

enum read_request_status {
    READ_REQUEST_INCOMPLETE = 0,
    READ_REQUEST_COMPLETE = 1,
    READ_REQUEST_ERROR = -1
};

enum write_request_status {
    WRITE_REQUEST_INCOMPLETE = 0,
    WRITE_REQUEST_COMPLETE = 1,
    WRITE_REQUEST_ERROR = -1
};

/* Read HTTP request until finding double CRLF indicating end of headers */
enum read_request_status read_http_request(req_context *c)
{
    char ch;
    int  rc;

    enum {
        R_START = 0,
        R_GOT_CR,
        R_GOT_CRLF,
        R_GOT_CRLFCR
    } reading_stage = R_START;


    /* Try to read one byte at a time */
    while ((rc = my_read(c, &ch)) == 1) 
    {
        
        if (c->total_read >= MAX_REQUEST_SIZE) {
            // too large
            return READ_REQUEST_ERROR;
        }

        // Detect request end
        switch (reading_stage) 
        {
            case R_START:
                if (ch == CR)
                    reading_stage = R_GOT_CR;
                break;
                
            case R_GOT_CR:
                if (ch == LF)
                    reading_stage = R_GOT_CRLF;
                else
                    reading_stage = R_START;
                break;
                
            case R_GOT_CRLF:
                if (ch == CR)
                    reading_stage = R_GOT_CRLFCR;
                else
                    reading_stage = R_START;
                break;
                
            case R_GOT_CRLFCR:
                if (ch == LF)
                    return READ_REQUEST_COMPLETE;
                reading_stage = R_START;
                break;
        }
    }

    /* Handle read errors */
    if (rc < 0) 
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Not ready to read, return incomplete */
            return READ_REQUEST_INCOMPLETE;
        }
        /* Real error occurred */
        return READ_REQUEST_ERROR;
    }

    /* EOF before complete request */
    if (rc == 0) 
    {
        return READ_REQUEST_ERROR;
    }

    /* Need more data */
    return READ_REQUEST_INCOMPLETE;
}

void mod_fd_read(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epollfd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

void mod_fd_write(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epollfd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

// Function to handle an incoming HTTP request
void handleClient(req_context *c) 
{
    int  connfd = c->connfd;
    char ch;
    int  rc;

    if(c->state == READING)
    {
        char rc;

        switch (read_http_request(c))
        {
            case READ_REQUEST_INCOMPLETE:
                c->state = READING;
                // should be thread safe
                mod_fd_read(c);
                return;
            case READ_REQUEST_COMPLETE:
                c->state = WRITING;
                mod_fd_write(c);
                break;
            case READ_REQUEST_ERROR:
                c->state = DONE;
                std::string error_resp = http_server.build_error_response(INTERNAL_SERVER_ERROR, "Internal Server Error");
                write_response(c, response);
                close(c->connfd);
                free_req_context(c);
                return;
        }

        http_server.send_response_header(c);
    }

    if(c->state == WRITING)
    {
        send_requested_file(c);
    }

    std::string request(buffer);
    std::cout << request;
    std::string request_line = request.substr(0, request.find("\r\n"));

    // Handle GET /
    if (request_line.find("GET / HTTP/1.1") != std::string::npos) 
    {
        std::string htmlContent = readHTMLFromFile("./ideas/hierarchy.html");
        if (htmlContent.empty()) {
            std::cerr << "Error: Could not load the HTML file. Exiting." << std::endl;
            return;
        }

        std::string httpResponse = "HTTP/1.1 200 OK\r\n";
        httpResponse += "Content-Type: text/html\r\n";
        httpResponse += "Access-Control-Allow-Origin: *\r\n";
        httpResponse += "Content-Length: " + std::to_string(htmlContent.size()) + "\r\n";
        httpResponse += "Connection: close\r\n\r\n";
        httpResponse += htmlContent;
        send(client_sock, httpResponse.c_str(), httpResponse.size(), 0);
    
    // Handle GET /buttons
    } else if (request_line.find("GET /data HTTP/1.1") != std::string::npos) 
    {
        // std::string jsonResponse = hashmapToJSON(buttons);
        std::string jsonResponse = "";

        try {
            Parser parser;
            parser.parse_file("./ideas/test.txt", buttons);
            jsonResponse = parser.get_json(); 
            // parser.save_json("output.json");
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }

        std::string httpResponse = "HTTP/1.1 200 OK\r\n";
        httpResponse += "Content-Type: application/json\r\n";
        httpResponse += "Access-Control-Allow-Origin: *\r\n";
        httpResponse += "Content-Length: " + std::to_string(jsonResponse.size()) + "\r\n";
        httpResponse += "Connection: close\r\n\r\n";
        httpResponse += jsonResponse;
        send(client_sock, httpResponse.c_str(), httpResponse.size(), 0);
    
    // Handle POST /action
    } 
    else if (request_line.find("POST /action HTTP/1.1") != std::string::npos) 
    {
        /* The entity body is separated from the headers by a null line */
        std::string body = request.substr(request.find("\r\n\r\n") + 4);
        cJSON *json = cJSON_Parse(body.c_str());

        if (json) 
        {
            cJSON *actionItem = cJSON_GetObjectItem(json, "action");
            if (actionItem) {
                std::string action = actionItem->valuestring;
                
                // Log the action for debugging
                std::cout << "Action received: " << action << std::endl;

                // executeCommand(action);  // Replace this with any other application

                // Respond to the client
                std::string httpResponse = "HTTP/1.1 200 OK\r\n";
                httpResponse += "Access-Control-Allow-Origin: *\r\n";
                httpResponse += "Content-Length: 0\r\n";
                httpResponse += "Connection: close\r\n\r\n";
                send(client_sock, httpResponse.c_str(), httpResponse.size(), 0);

                executeCommand(buttons[action]);  
            }
            cJSON_Delete(json);
        }
    }
    else if (request_line.find("POST /add-button HTTP/1.1") != std::string::npos) 
    {
        std::string body = request.substr(request.find("\r\n\r\n") + 4);
        cJSON *json = cJSON_Parse(body.c_str());

        if (json) 
        {
            cJSON *actionItem = cJSON_GetObjectItem(json, "action");
            cJSON *labelItem = cJSON_GetObjectItem(json, "label");

            if (actionItem) {
                std::string action = actionItem->valuestring;
                std::string label = labelItem->valuestring;
                
                buttons[label] = action;

                for (const auto& pair : buttons) {
                    std::cout << "Action: " << pair.first << ", Label: " << pair.second << std::endl;
                }
                appendToFile(label, action, "./data/buttons.txt");
                
                // Log the action for debugging
                std::cout << "Action received: " << action << std::endl;

                // executeCommand(action);  

                // Create JSON response
                cJSON *response = cJSON_CreateObject();
                cJSON_AddBoolToObject(response, "success", true);
                char *jsonString = cJSON_Print(response);

                // Respond to the client
                std::string httpResponse = "HTTP/1.1 200 OK\r\n";
                httpResponse += "Content-Type: application/json\r\n";
                httpResponse += "Access-Control-Allow-Origin: *\r\n";
                httpResponse += "Content-Length: " + std::to_string(strlen(jsonString)) + "\r\n";
                httpResponse += "Connection: close\r\n\r\n";
                httpResponse += jsonString;

                send(client_sock, httpResponse.c_str(), httpResponse.size(), 0);
                free(jsonString);

                executeCommand(action);  
            }
            cJSON_Delete(json);
        }
    }
    else
    {
        std::string htmlContent = R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>404 Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    h1 { font-size: 50px; }
                    p { font-size: 20px; color: #666; }
                </style>
            </head>
            <body>
                <h1>404</h1>
                <p>The page you are looking for was not found.</p>
                <p><a href="/">Go to Home Page</a></p>
            </body>
            </html>
        )";

        std::string notFoundResponse = "HTTP/1.1 404 Not Found\r\n";
        notFoundResponse += "Access-Control-Allow-Origin: *\r\n";
        notFoundResponse += "Content-Type: text/html\r\n";
        notFoundResponse += "Content-Length: " + std::to_string(htmlContent.size()) + "\r\n";
        notFoundResponse += "Connection: close\r\n\r\n";
        notFoundResponse += htmlContent;

        send(client_sock, notFoundResponse.c_str(), notFoundResponse.size(), 0);
    }
}

/*
    Whenever we fork children, we must wait for them to prevent them from becoming zombies.
 */
void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    /* 
        WNOHANG option tells waitpid not to block if there exist 
        running children that have not yet terminated. 
    */
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void serializeMap(const std::unordered_map<std::string, std::string>& map, const std::string& filename) 
{
    std::ofstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Could not open file for writing\n";
        return;
    }

    for (const auto& pair : map) {
        file << pair.first << ":" << pair.second << "\n";  // Using ':' as a delimiter
    }

    file.close();  
}

void deserializeMap(std::unordered_map<std::string, std::string>& map, const std::string& filename) 
{
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Could not open file for reading\n";
        return;
    }

    std::string line;

    while (std::getline(file, line)) 
    {
        size_t delimiterPos = line.find(':');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            map[key] = value;
        }
    }

    file.close();
}

void signalHandler(int signum) 
{
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    std::cout << "\nClosing Server......\n";

    // for (const auto& pair : buttons) {
    //     std::cout << pair.first << ":" << pair.second << "\n";  // Using ':' as a delimiter
    // }
    // serializeMap(buttons, "./data/buttons.txt");

    exit(signum);
}

int new_socket(const char *ip, const char *port)
{
    struct addrinfo hints, *res, *p;
    int listenfd;
    int yes=1;

    memset(&hints, 0, sizeof(hints));     // Make sure its clean
    hints.ai_family   = AF_UNSPEC;        // use IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;      // TCP
    hints.ai_flags    = AI_PASSIVE;       // (wildcard IP address bind)

    /* Make it protocol independent */
    int err = 0;
    if ((err = getaddrinfo(ip, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(1);
    }

    /*
        the linked list may have more than one addrinfo structure
        the application should try using the addresses in the order
        in which they are returned until we successfully bind
    */
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
    if (listen(listenfd, BACKLOG) < 0) {
        std::cerr << "Listen failed" << std::endl;
        return -1;
    }

    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));

    freeaddrinfo(res);  // not needed anymore
    
    char name[1024];
    gethostname(name, 1024);

    std::cout << "Server listening on " << name <<  " http://" << ipstr << ':' << PORT << std::endl;

    return listenfd;
}

void clientThread(req_context *state)
{
    handleClient(state,buffer);
}

constexpr int MAX_EVENTS = 64;

class ServerException : public std::runtime_error {
public:
    explicit ServerException(const std::string& message) 
        : std::runtime_error(message) {}
};

struct Socket
{
    int sockfd;
    constexpr int BACKLOG = 10;

    Socket():sockfd(-1)
    {
    }

    Socket(const char *ip, const char *port):sockfd(-1)
    {
        struct addrinfo hints, *res, *p;

        memset(&hints, 0, sizeof(hints));     // Make sure its clean
        hints.ai_family   = AF_UNSPEC;        // use IPv4 or IPv6, whichever
        hints.ai_socktype = SOCK_STREAM;      // TCP
        hints.ai_flags    = AI_PASSIVE;       // fill in my IP for me

        /* Make it protocol independent */
        if (getaddrinfo(ip, port, &hints, &res) < 0) {
            throw ServerException(std::string("getaddrinfo error: ") + gai_strerror(err));
        }

        std::string last_error;

        for(p = res; p != NULL; p = p->ai_next) 
        {
            // Create a TCP/IP stream socket
            if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
                last_error = std::string("Socket creation failed: ") + std::strerror(errno);
                continue;
            }

            set_non_blocking(sockfd);
            set_opt_reuse_addr();

            // bind the port to the socket
            if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
                last_error = std::string("Binding failed: ") + std::strerror(errno);
                close(sockfd);
                continue;
            }
            break;
        }    

        // not needed anymore
        freeaddr_info(res);

        // didnt bind
        if(p == NULL){
            throw ServerException("Failed to bind to any address. Last error: " + last_error);
        }
    }

    ~Socket()
    {
        if (sockfd != -1) {
            close(sockfd);
        }
    }

    // remove copy constructor
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    void listen()
    {
        /* Convert socket to listening socket */
        if (::listen(sockfd, BACKLOG) < 0) {          // calling POSIX listen not my listen :)
            throw ServerException(std::string("Listen failed: ") +  std::strerror(errno));
        }

        std::cout << "Server listening on " << getHostName() <<  " http://" << getHostIpAddress() << ':' << PORT << std::endl;
    }

    int accept_connection()
    {
        int connfd;
        struct sockaddr_storage client_addr;
        socklen_t cl_addr_len = sizeof(client_addr);

        /*  A new descriptor is returned by accept for each client that connects to the server. */
        if ((connfd = accept(sockfd, (struct sockaddr *)&client_addr, &cl_addr_len)) < 0) {
            throw ServerException(std::string("Accept failed : ") +  std::strerror(errno));
        }

        std::cout << "Client connected from IP: " << getIpAddress((struct sockaddr *)&client_addr);

        return connfd;
    }

    int get_socket() const 
    {
        return sockfd;
    }

    std::string getHostIpAddress() 
    {
        struct utsname unameData;
        
        // Get the hostname using uname
        if (uname(&unameData) == -1) {
            perror("uname");
            return "Error getting hostname";
        }
        std::string hostname = unameData.nodename;

        // Get host information by hostname
        struct hostent *host = gethostbyname(hostname.c_str());
        if (host == NULL) {
            herror("gethostbyname");
            return "Error getting host information";
        }

        // Extract the IP address (only the first address)
        struct in_addr **addrList = (struct in_addr **)host->h_addr_list;
        if (addrList[0] != nullptr) {
            return std::string(inet_ntoa(*addrList[0]));
        }

        return "No IP address found";
    }

    std::string getHostName() 
    {
        char hostname[256]; // Buffer to store the hostname
        
        // Call gethostname to get the name of the host
        if (gethostname(hostname, sizeof(hostname)) == -1) {
            perror("gethostname");
            return "Error getting hostname";
        }
        
        return std::string(hostname); // Convert to std::string
    }

    std::string getIpAddress(struct sockaddr *sa) 
    {
        char ipstr[INET6_ADDRSTRLEN]; 
        void *addr = nullptr;

        switch (sa->sa_family) {
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

    void set_non_blocking(int fd)
    {
        // file control : set socket for nonblocking I/O
        // beware not to clear all the other file status flags. 
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    }

    void set_opt_reuse_addr(bool on = true)
    {
        // Prevent the "Address already in use" error message
        int optval = on ? 1:0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            std::cerr << "setsockopt error" << std::endl;
            exit(1);
        }
    }

    void set_opt_keep_alive(bool on) 
    {
        int optval = on ? 1 : 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval,sizeof(optval)) < 0) {
            std::cerr << "setsockopt error" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // Disable Nagle's Algorithm
    void set_opt_tcp_no_delay(bool on) 
    {
        int optval = on ? 1 : 0;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval,sizeof(optval)) < 0) {
            std::cerr << "setsockopt error" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // allows data to be sent in the SYN packet, speeding up 
    // connection setup for subsequent connections to the same server.
    void set_opt_tcp_fast_open(bool len)
    {
        int qlen = len;  
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) < 0) {
            perror("Failed to set TCP_FASTOPEN");
        }
    }    

    void set_opt_tcp_quick_ack(bool on)
    {
        int quickack = on ? 1 : 0;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack)) < 0) {
            perror("Failed to set TCP_QUICKACK");
        }
    }

    void set_opt_linger()
    {
        struct linger linger_opt = {1, 10};  // Enable linger with a 10-second timeout
        if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) < 0) {
            perror("Failed to set SO_LINGER");
        }
    }

    void set_opt_rcvbuf(int bufsize) 
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
            std::cerr << "setsockopt error for SO_RCVBUF" << std::endl;
            exit(1);
        }
    }

    void set_opt_sndbuf(int bufsize) 
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
            std::cerr << "setsockopt error for SO_SNDBUF" << std::endl;
            exit(1);
        }
    }
}

struct EventPoll
{
    Socket socket;
    int epoll_fd;

    static constexpr int MAX_EVENTS     = 32;
    static constexpr int LISTEN_BACKLOG = 128;

    std::function<void(req_status*)> client_handler_ = nullptr;

    // when epoll_wait returns, this array is modified to indicate information
    // about the subset of file descriptors in the interest list that are in the ready state
    EventPoll(const char *ip, const char *port, std::function<void(req_status*)> client_handler)
        :client_handler_(client_handler)
    {

        socket = Socket(ip, port)
        socket.listen();

        // creates a new epoll instance and returns a file descriptor referring to that instance.
        if ((epoll_fd = epoll_create1(0)) < 0) {
            throw ServerException(std::string("Failed to create epoll instance") +  std::strerror(errno));
        }

        // Add listener socket to epoll, register it in edge triggered mode 
        poll.register_fd(socket.get_socket(), (EPOLLIN | EPOLLET));
    }

    EventPoll(const char *port)
    {
        EventPoll(NULL, port);
    }

    void register_fd(int fd, int event_flags)
    {
        struct epoll_event ev;
        ev.events = event_flags;
        ev.data.fd = fd;

        // registering interest in a particular file descriptor
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) 
        {
            throw ServerException(std::string("Failed to add listener to epoll") +  std::strerror(errno));
        }
    }

    int register_fd_ctx(req_context *c, int event_flags)
    {
        struct epoll_event ev;
        ev.events = event_flags;
        ev.data.ptr = c;

        // registering interest in a particular file descriptor
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) 
        {
            return -1;
        }

        return 0;
    }

    void rm_fd(int fd) 
    {
        struct epoll_event ev;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev) == -1) {
            std::cerr << "Failed to remove fd from epoll" << std::endl;
            exit(1);
        }
    }

    void mod_fd_read(int fd)
    {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
        ev.data.ptr = /**/;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            std::cerr << "Failed to remove fd from epoll" << std::endl;
            exit(1);
        }
    }

    void mod_fd_write(int fd)
    {
        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
        ev.data.ptr = /**/;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            std::cerr << "Failed to remove fd from epoll" << std::endl;
            exit(1);
        }
    }

    void event_loop()
    {
        struct epoll_event events[MAX_EVENTS]; 

        for(;;) 
        {
            // waits for I/O events, blocking the calling thread if no events are currently available.
            // TODO: set timeout
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

            if (nfds <= 0) 
            {
                if (errno == EINTR) {
                    // interrupted by a signal, try again
                    continue;
                }
                std::cerr << "epoll_wait failed: " << strerror(errno) << std::endl;
                break;
            }

            // one or more file descriptors in the interest list became ready
            for(int i = 0; i < nfds; i++)
            {
                if (events[i].data.fd == listen_fd_) 
                {
                    // handle connection if listener is ready
                    handle_new_connections();
                } 
                else 
                {
                    handle_client_data(events[i].data.ptr);
                }
            }
        }
    }


    void handle_new_connections() 
    {
        for(;;)
        {
            /*  A new descriptor is returned by accept for each client that connects to the server. */
            int connfd = socket.accept_connection();

            // apply non-blocking IO to the connection sockets as well
            socket.set_non_blocking(connfd);
            
            req_context* c = new_req_context(connfd, epoll_fd);

            /*
                - Associated file is available for read operations
                - Requests edge-triggered notification for the associated file descriptor.
                - Requests one-shot notification for the associated file descriptor
                - I will rearm it based on state with maybe a new event mask
            */
            if (register_fd_ctx(c,(EPOLLIN | EPOLLET | EPOLLONESHOT)) < 0) 
            {
                // failed to register client, free memory and try again
                delete_req_context(c);
                close(connfd);
                continue;
            }
        }
    }

    void handle_client_data(void* data) 
    {
        req_status* context = static_cast<req_context*>(data);

        if (client_handler_) 
        {
            thread_pool_.QueueJob([this, context]() {
                client_handler_(context);
            });
        }
    }

    static void* get_in_addr(struct sockaddr* sa) 
    {
        if (sa->sa_family == AF_INET) {
            return &(((struct sockaddr_in*)sa)->sin_addr);
        }
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
};

int main(void) 
{
    int listenfd;
    int connfd;

    char remoteIP[INET6_ADDRSTRLEN];

    ThreadPool pool;

    signal(SIGINT, signalHandler);

    if((listenfd = new_socket(NULL, PORT))<0){
        std::cerr << "Error: couldnt create a socket file descriptor." << std::endl;
        exit(1);
    }
    /*
        e_poll monitors multiple file descriptors to see if I/O is possible on any of them. 

        when epoll_wait returns, this array is modified to indicate information about the 
        subset of file descriptors in the interest list that are in the ready state
     */
    struct epoll_event events[MAX_EVENTS];
    
    // creates a new epoll instance and returns a file descriptor referring to that instance.
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        std::cerr << "Failed to create epoll instance" << std::endl;
        exit(1);
    }

    // Add listener socket to epoll 
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;  // edge triggered
    ev.data.fd = listenfd;

    // registering interest in a particular file descriptor
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listenfd, &ev) < 0) {
        std::cerr << "Failed to add listener to epoll" << std::endl;
        exit(1);
    }

    /*
        - for reaping zombie processes that appear as the fork()ed child processes exit. 

        - If a process terminates, and that process has children in the zombie state,
        the parent process ID of all the zombie children is set to 1 (the init process),
        which will inherit the children and clean them up

        - Whenever we fork children, we must wait for them to prevent them from becoming zombies.
        To do this we establish a signal handler to catch SIGCHLD and within the handler we call wait . 
     */

    #if fork 
        struct sigaction sa;
        sa.sa_handler = sigchld_handler; // reap all dead processes
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            perror("sigaction");
            exit(1);
        }
    #endif


    for(;;) 
    {
        // waits for I/O events (or interrupts), blocking the calling thread if no events are currently available.
        // timeout of -1 causes epoll_wait() to block indefinitely
        // TODO: set timeout
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (nfds <= 0) {
            // most likely interrupted by a signal handler
            std::cerr << "epoll_wait failed" << std::endl;
            continue;
        }

        for(int i = 0; i < nfds; i++)
        {
            // handle connection if listener is ready
            if(events[i].data.fd == listenfd)
            {                
                while(1) // may handle multiple connections at the same time
                {
                    struct sockaddr_storage client_addr;
                    socklen_t cl_addr_len = sizeof(client_addr);

                    /*  A new descriptor is returned by accept for each client that connects to the server. */
                    if ((connfd = accept(listenfd, (struct sockaddr *)&client_addr, &cl_addr_len)) < 0) 
                    {
                        if(errno == EGAIN | errno == EWOULDBLOCK){      // error occured not just nothing to accept
                            std::cerr << "Accept failed" << std::endl;
                        }
                        break;
                    }

                    // apply non-blocking IO to the connection sockets as well
                    set_non_blocking(connfd);

                    struct epoll_event ev;

                    // associated file is available for read operations
                    // Requests edge-triggered notification for the associated file descriptor.
                    // Requests one-shot notification for the associated file descriptor
                    // I will rearm it based on state with maybe a new event mask
                    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;

                    req_status *status = new_req_context(connfd);
                    // keep the state     
                    ev.data.ptr = status;

                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
                        std::cerr << "Failed to add client to epoll" << std::endl;
                        close(connfd);
                        continue;
                    }

                    inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), remoteIP, INET6_ADDRSTRLEN);
                    printf("Client connected from IP: %s\n", remoteIP); 
                }
            }
            else
            {
                // Handle client data
                req_status *status = events[i].data.ptr;

                 // not null terminated
                pool.QueueJob([status](void) {
                    clientThread(status);
                });
            }
        }
    }
    return 0;
}