#include <iostream>
#include <fstream> 

#include <vector>
#include <string>
#include <string_view>
#include <queue>
#include <unordered_map>

#include <functional>

#include <thread>
#include <condition_variable>
#include <atomic>
#include <mutex>

#include <cstring> 
#include <cerrno>
#include <ctime>

#include <unistd.h>
#include <cstdlib> 
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>

#include <netinet/in.h>
#include <netinet/tcp.h>  // For TCP_NODELAY
#include <arpa/inet.h> 
#include <linux/limits.h> 

#include "cJSON.h"

// #include "Parser.h"

using namespace std::literals;

#define PORT                "8080"    // the port users will be connecting to
#define MAX_REQUEST_SIZE    8192U     // cap it at 8K  

#define CR                  '\r'
#define LF                  '\n'


/* ----------------------- UTILS---------------------------------*/
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
    outFile.open(filename, std::ios::app); 
    if (!outFile) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }
    outFile << label << ":" << action << std::endl;
    outFile.close();
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
static constexpr std::array<std::string_view, 9> valid_methods =
{
    "GET", "POST", "PUT", "DELETE", "HEAD", 
    "OPTIONS", "PATCH", "TRACE", "CONNECT"
};

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
        }
        delete c;
    }
}


/* From W. Richard Stevens - UNIX Network Programming */
/* Write may actually write less than expected for various reasons (interrupts, ..) */
ssize_t                     /* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, ssize_t n)
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
static ssize_t readn(req_context *c, char *ptr)
{
    // check if the buffer still contains data
    if (c->read_cnt <= 0) {
again:
        // all bytes are read, read more from the file
        if ((c->read_cnt = read(c->connfd, (c->read_buf + c->total_read), MAX_REQUEST_SIZE - c->total_read)) < 0) {
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
        // read_cnt should be positive
        c->read_ptr     = c->read_buf;
        c->total_read  += (size_t)c->read_cnt;
    }

    // buffer still contains data, return one byte at a time using *ptr
    c->read_cnt--;
    *ptr = *c->read_ptr++;
    // read successfully
    return(1);
}


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
    HTTPBuilder() 
    {
        // Reserve data upfront to limit reallocations
        response.reserve(4096); 

        body.reserve(1024);
        body_size.reserve(16);

        date.reserve(64);
        ext.reserve(16);

        headers.reserve(2048);
    }

    HTTPBuilder& http_resp_add_status(int idx) 
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

        headers += "Content-Length: ";
        headers += body_size;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_content_type(std::string_view type) 
    {
        headers += "Content-Type: ";
        headers += type;
        headers += "\r\n";
        return *this;
    }

    std::string_view http_get_content_type(std::string_view file_path) 
    {
        ext.clear();
        // get type from extension
        auto pos = file_path.find_last_of('.');
        if (pos != std::string::npos) {
            ext += file_path.substr(pos + 1);
            // get it from the map
            auto it = mime_types.find(ext);
            if (it != mime_types.end()) {
                return it->second;  
            }
        }
        return "application/octet-stream";
    }

    HTTPBuilder& http_resp_add_content_encoding(std::string_view encoding) 
    {
        headers += "Content-Encoding: ";
        headers += encoding;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_allow(std::string_view methods) 
    {
        headers += "Allow: ";
        headers += methods;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_authorization(std::string_view auth) 
    {
        headers += "Authorization: ";
        headers += auth;
        headers += "\r\n";
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
            headers += "Date: ";
            headers += std::string_view(date);
            headers += "\r\n";
        }
        return *this;
    }

    HTTPBuilder& http_resp_add_expires(std::string_view expires)
    {
        headers += "Expires: ";
        headers += expires;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_last_modified(std::string_view last_modified) 
    {
        headers += "Last-Modified: ";
        headers += last_modified;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_location(std::string_view location) 
    {
        headers += "Location: ";
        headers += location;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_referer(std::string_view referer) 
    {
        headers += "Referer: ";
        headers += referer;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_server(std::string_view server_name) 
    {
        headers += "Server: ";
        headers += server_name;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_user_agent(std::string_view user_agent) 
    {
        headers += "User-Agent: ";
        headers += user_agent;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_www_auth(std::string_view auth) 
    {
        headers += "WWW-Authenticate: ";
        headers += auth;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_access_auth(std::string_view access_auth) 
    {
        headers += "Access-Control-Allow-Origin: ";
        headers += access_auth;
        headers += "\r\n";
        return *this;
    }

    HTTPBuilder& http_resp_add_custom_header(std::string_view key, std::string_view value) 
    {
        headers += key;
        headers += ": ";
        headers += value;
        headers += "\r\n";
        return *this;
    }

    /*
        Finally build the constructed respnse header
    */
    std::string& build() 
    {
        response.clear();

        // status line
        response += "HTTP/1.0 ";
        response += std::to_string(codes[status_code].code);
        response += " ";
        response += codes[status_code].reason;
        response += "\r\n";

        response += headers;

        headers.clear();

        // Append body if available (when dynamic response is required i.e not serving a static file)
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

    /* Maybe do something with them later */
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    size_t header_count = 0;

public:

    HTTPParser(){
        method.reserve(16);
        uri.reserve(128);
        version.reserve(16);

        headers.reserve(32); 
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
        auto end_of_line = request.find("\r\n"sv);
        if (end_of_line == std::string_view::npos) {
            return BadRequest; 
        }

        std::string_view request_line = request.substr(0, end_of_line);

        auto first_space = request_line.find(' ');
        if (first_space == std::string_view::npos){
            return BadRequest; 
        }

        // Extract method
        method += std::string(request_line.substr(0, first_space));

        if(!is_method_valid(method))
        {
            return BadRequest;
        }

        auto second_space = request_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos) {
            return BadRequest; 
        }

        // Extract URI
        uri += std::string(request_line.substr(first_space + 1, second_space - first_space - 1));

        // Extract version
        version += std::string(request_line.substr(second_space + 1));

        if (version.substr(0, 5) != "HTTP/") {
            return BadRequest; 
        }

        if (version != "HTTP/1.0" && version != "HTTP/1.1") {
            return InternalServerError;  
        }

        return parse_headers(request.substr(end_of_line + 2));  
    }

    StatusCode parse_headers(std::string_view headers_view) 
    {
        header_count = 0;

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

            std::string_view header_name = line.substr(0, colon_pos);
            std::string_view header_value = line.substr(colon_pos + 1);

            // Trim whitespace from header value, handle when all header value is whitespace
            header_value.remove_prefix(
                std::min(header_value.find_first_not_of(" \t"), header_value.size())
            );
            header_value.remove_suffix(
                header_value.size() - header_value.find_last_not_of(" \t") - 1
            );

            headers.emplace_back(header_name,header_value);
            header_count++;
        }
        // no empty line found
        return BadRequest;
    }

    static bool is_method_valid(std::string_view method) 
    {
        return std::find(valid_methods.begin(), valid_methods.end(), method) != valid_methods.end();
    }

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

    // Get specific header value
    std::string_view get_header(std::string_view name) const 
    {
        for (size_t i = 0; i < header_count; i++) {
            if (headers[i].first == name) {
                return headers[i].second;
            }
        }
        return {};
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

    using RequestHandler = std::function<std::string&(req_context *c)>;
    std::unordered_map<std::string, std::unordered_map<std::string, RequestHandler>> route_handlers;

public:
    HTTPServer(std::string root_dir = "./Web")
    {
        char absolute_path[PATH_MAX]; 

        // verify absolute path of root directory
        if(!realpath(root_dir.c_str(), absolute_path)){
            std::cerr << "root path error:" <<  std::strerror(errno) << std::endl;
            exit(1);
        }

        root_directory.assign(absolute_path, PATH_MAX);
        setup_default_routes();
    }

    void setup_default_routes() 
    {
        add_route("GET", "/", [this](req_context *c) -> std::string& {
            return response_static_file(c, "/index.html");
        });

        add_route("GET", "/about", [this](req_context *c) -> std::string& {
            return response_static_file(c, "/about.html");
        });
    }

    void add_route(const std::string& method, const std::string& path, RequestHandler handler) 
    {
        route_handlers[method][path] = handler;
    }


    std::string& response_static_file(req_context *c, const std::string& uri)
    {
        size_t original_length = strlen(root_directory.c_str());

        root_directory += uri;

        // get full path
        char abs_path[PATH_MAX];
        if (realpath(root_directory.c_str(), abs_path) == NULL){
            return build_error_response(BadRequest, "Invalid path");
        }

        // Restore rootdirectory to its original state
        root_directory.resize(original_length);

        std::string_view file_path = abs_path;

        // Double check nothing is going on
        if (file_path.substr(0, original_length) != root_directory) {
            return build_error_response(BadRequest, "Invalid path");
        }

        size_t file_size;
        FILE *file = get_file_info(abs_path, file_size);

        if(!file){
            return build_error_response(NotFound, "Resource not found");
        }

        c->req_file      = file;
        c->remaining     = file_size;

        return build_success_response(OK, file_path, file_size);
    }


    std::string_view response_body(int status, const std::string& message)
    {
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type("text/html")
            .http_resp_add_content_body(
                "<html><body><h1>Error " + std::to_string(status) + "</h1>"
                "<p>" + message + "</p></body></html>")
            .build();
    }

    void send_response_header(req_context *c)
    {
        std::string response;

        switch(parser.parse_request(c->read_buf))
        {
            case OK:
            {
                const std::string& method = parser.get_method();
                const std::string& uri    = parser.get_uri();

                /*
                    - Many operating systems use ".." as a path component to indicate a
                      directory level above the current one

                    - an HTTP server must disallow any such construct in the Request-URI if it
                      would otherwise allow access to a resource outside those intended to
                      be accessible via the HTTP server.
                */
                if (uri.find("..") != std::string::npos) {
                    response = build_error_response(BadRequest, "Invalid path");
                    break;
                }

                if (route_handlers.find(method) == route_handlers.end()) {
                    response = build_error_response(BadRequest, "Method not allowed");
                    break;
                }

                // Check if route exists for this method
                auto& method_routes = route_handlers[method];

                // If there is no handle we will try to serve a static file 
                if (method_routes.find(uri) == method_routes.end()) 
                {
                    if (method == "GET") 
                    {
                        response = response_static_file(c, uri);
                        break;
                    }
                }
                else
                {
                    response = route_handlers[method][uri](c);
                    break;
                }
                break;
            }
            
            case BadRequest:
                response = build_error_response(BadRequest, "Bad Request");
                break;
            
            case InternalServerError:
                response = build_error_response(InternalServerError, "Internal Server Error");
                break;
            
            default:
                response = build_error_response(InternalServerError, "Internal Server Error");
                break;
        }

        write_response(c, response);
    }

    void write_response(req_context *c , std::string& response)
    {
        if(writen(c->connfd, response.c_str(), (ssize_t)response.size())<0){
            std::cerr << "Error while sending the response header" << std::endl;
        }
    }

    enum write_req_status send_response_file(req_context *c)
    {
        FILE *file = c->req_file;

        if(file==nullptr)
        {
            return WRITE_REQUEST_COMPLETE;
        }

        int filefd = fileno(file);
        size_t left = c->remaining;

        ssize_t writen;

        while (left > 0) 
        {
            // Check file size
            off_t file_size;
            if ((file_size = lseek(filefd, 0, SEEK_END)) == -1) {
                perror("lseek failed");
            }
            // Reset position to beginning
            lseek(filefd, 0, SEEK_SET);

            /* 
                The sendfile() function in Linux lets you tell 
                the kernel to send part or all of a file. 
             */
            writen = sendfile(c->connfd, filefd, NULL, left);

            if (writen < 0) 
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    return WRITE_REQUEST_ERROR;
                }
            } 
            else if (writen == 0) 
            {
                return WRITE_REQUEST_ERROR;
            } 
            else
            {
                // writen should be positive
                left -= (size_t)writen;
            }
        }

        if (left == 0) {
            return WRITE_REQUEST_COMPLETE;
        } else {
            c->remaining = left;
            return WRITE_REQUEST_INCOMPLETE;
        }
    }

    std::string& build_error_response(int status, const std::string& message) 
    {
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type("text/html")
            .http_resp_add_content_body(
                "<html><body><h1>Error " + std::to_string(status) + "</h1>"
                "<p>" + message + "</p></body></html>")
            .build();
    }

    std::string& build_success_response(int status, const std::string_view file_path, const size_t file_size) 
    { 
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type(builder.http_get_content_type(file_path))
            .http_resp_add_content_length(file_size)
            .build();
    }

    FILE *get_file_info(const char* filepath, size_t &size) 
    {
        ssize_t file_size = -1; 

        FILE *file = fopen(filepath, "rb");

        if(!file){
            return NULL;
        }

        fseek(file, 0L, SEEK_END);
        if((file_size = ftell(file)) < 0){
            std::cerr << "ftell failed ! : " << std::strerror(errno) << std::endl;
        }
        size = (size_t)file_size;
        fseek(file, 0L, SEEK_SET);

        return file;
    }
};

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



/* Read HTTP request until finding double CRLF indicating end of headers */
enum read_req_status read_http_request(req_context *c)
{
    char ch;
    ssize_t  rc;

    enum {
        R_START = 0,
        R_GOT_CR,
        R_GOT_CRLF,
        R_GOT_CRLFCR
    } reading_stage = R_START;

    /* Try to read one byte at a time */
    while ((rc = readn(c, &ch)) == 1) 
    {
        if (c->total_read >= MAX_REQUEST_SIZE) {
            // cap it at 8k
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
                if (ch == LF){
                    // done
                    return READ_REQUEST_COMPLETE;
                }
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
        std::cerr << "Error occurred while reading : " << std::strerror(errno) << std::endl;
    }

    /* EOF before complete request */
    if (rc == 0) 
    {
       /* Real error occurred */
        std::cerr << "EOF received, client may have disconnected : " << std::strerror(errno) << std::endl;
        return READ_REQUEST_COMPLETE;
    }

    /* Need more data */
    return READ_REQUEST_INCOMPLETE;
}

void mod_fd_read(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

void mod_fd_write(req_context *c)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
    ev.data.ptr = c;
    if (epoll_ctl(c->epoll_fd, EPOLL_CTL_MOD, c->connfd, &ev) == -1) {
        std::cerr << "Failed to remove fd from epoll" << std::endl;
    }
}

// Function to handle an incoming HTTP request
void handleClient(req_context *c) 
{
    if(c->state == READING)
    {
        switch (read_http_request(c))
        {
            case READ_REQUEST_INCOMPLETE:
                c->state = READING;
                // should be thread safe
                mod_fd_read(c);
                return;
            case READ_REQUEST_COMPLETE:
                c->state = WRITING;

                // mod_fd_write(c);
                break;
            case READ_REQUEST_ERROR:
                c->state = DONE;
                std::string& error_resp = http_server.build_error_response(InternalServerError, "Internal Server Error");
                http_server.write_response(c, error_resp);

                if(c->req_file){
                    fclose(c->req_file);
                    c->req_file = nullptr;
                }
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
                mod_fd_write(c);
                break;

            case WRITE_REQUEST_COMPLETE:
                c->state = DONE;
                if(c->req_file)
                {
                    fclose(c->req_file);
                    c->req_file = nullptr;
                }
                if(c->connfd)
                {
                    close(c->connfd);
                }
                delete_req_context(c);
                break;

            case WRITE_REQUEST_ERROR:
                c->state = DONE;
                if(c->req_file){
                    fclose(c->req_file);
                    c->req_file = nullptr;
                }
                if(c->connfd)
                {
                    close(c->connfd);
                }
                delete_req_context(c);
                break;

        }
    }
#if 0
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
#endif
}

/*
    Whenever we fork children, we must wait for them to prevent them from becoming zombies.
 */
void sigchld_handler(void)
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


class ServerException : public std::runtime_error {
public:
    explicit ServerException(const std::string& message) 
        : std::runtime_error(message) {}
};

struct Socket
{
    int sockfd;
    static constexpr int BACKLOG = 10; // how many pending connections queue will hold

    Socket(): sockfd(-1){}

    void tcp_socket(const char *ip, const char* port)
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
    }

    Socket(const Socket&) = delete;  
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : sockfd(other.sockfd) {
        other.sockfd = -1;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            if (sockfd != -1) {
                close(sockfd);
            }
            sockfd = other.sockfd;
            other.sockfd = -1;
        }
        return *this;
    }

    ~Socket()
    {
        if (sockfd != -1) {
            close(sockfd);
        }
    }

    void wait_connection()
    {
        /* Convert socket to listening socket */
        if (listen(sockfd, BACKLOG) < 0) {          // calling POSIX listen not my listen :)
            close(sockfd);
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
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                std::cerr << "Accept error : " << std::strerror(errno);
            }
            return -1;
        }

        std::cout << "Client connected from IP: " << getIpAddress((struct sockaddr *)&client_addr) << std::endl;

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
};

struct EventPoll
{
    Socket socket;
    ThreadPool thread_pool_; 

    int epoll_fd;

    std::function<void(req_context*)> client_handler_ = nullptr;

    static constexpr int MAX_EVENTS     = 32;
    static constexpr int LISTEN_BACKLOG = 128;

    // when epoll_wait returns, this array is modified to indicate information
    // about the subset of file descriptors in the interest list that are in the ready state
    EventPoll(const char *ip, const char *port, std::function<void(req_context*)> client_handler) :client_handler_(client_handler)
    {
        socket.tcp_socket(ip, port);
        socket.wait_connection();

        // creates a new epoll instance and returns a file descriptor referring to that instance.
        if ((epoll_fd = epoll_create1(0)) < 0) {
            throw ServerException(std::string("Failed to create epoll instance") +  std::strerror(errno));
        }

        // Add listener socket to epoll, register it in edge triggered mode 
        register_fd(socket.get_socket(), (EPOLLIN | EPOLLET));
    }

    EventPoll(const char* port,  std::function<void(req_context*)> client_handler) : EventPoll(NULL,port,client_handler){}

    void register_fd(int fd, uint32_t event_flags)
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

    int register_fd_ctx(req_context *c, uint32_t event_flags)
    {
        struct epoll_event ev;
        ev.events = event_flags;
        ev.data.ptr = c;

        // registering interest in a particular file descriptor
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->connfd, &ev) < 0) 
        {
            std::cerr << "Failed to register a file descriptor" << std::strerror(errno) << std::endl;
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
        // associated file is available for read operations
        // Requests edge-triggered notification for the associated file descriptor.
        // Requests one-shot notification for the associated file descriptor
        // I will rearm it based on state with maybe a new event mask
        ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
        // ev.data.ptr = /**/;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            std::cerr << "Failed to remove fd from epoll" << std::endl;
            exit(1);
        }
    }

    void mod_fd_write(int fd)
    {
        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
        // ev.data.ptr = /**/;
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
                throw ServerException(std::string("epoll_wait error : ") +  std::strerror(errno));
            }

            // one or more file descriptors in the interest list became ready
            for(int i = 0; i < nfds; i++)
            {
                if (events[i].data.fd == socket.get_socket()) 
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
            if(connfd < 0){
                return;
            }

            // apply non-blocking IO to the connection sockets as well
            socket.set_non_blocking(connfd);
            
            // new data structure to hold the context of the IO
            req_context* c = new_req_context(connfd, epoll_fd);

            /*
                - Associated file is available for read operations
                - Requests edge-triggered notification for the associated file descriptor.
                - Requests one-shot notification for the associated file descriptor
                - I will rearm it based on state with maybe a new event mask
            */
            if (register_fd_ctx(c, (EPOLLIN | EPOLLET | EPOLLONESHOT)) < 0) 
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
        req_context* context = static_cast<req_context*>(data);

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
    signal(SIGINT, signalHandler);

    EventPoll ep("8080", handleClient);
    ep.event_loop();

    return 0;
}