#include <iostream>
#include <fstream> 

#include <vector>
#include <string>
#include <string_view>
#include <queue>
#include <unordered_map>

#include <functional>

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
#include <ifaddrs.h>

#include "cJSON.h"
#include "Socket.h"
#include "ServerException.h"
#include "Parser.h"
#include "Server.h"
#include "HTTP.h"
#include "Server.h"

using namespace std::literals;

#define PORT                "8080"    // the port users will be connecting to

#define CR                  '\r'
#define LF                  '\n'

std::unordered_map<std::string, std::string> buttons;

extern status_code_t codes[];

/* Valid HTTP Methods */
constexpr std::array<std::string_view, 9> valid_methods =
{
    "GET", "POST", "PUT", "DELETE", "HEAD", 
    "OPTIONS", "PATCH", "TRACE", "CONNECT"
};

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
        Finally build the constructed respnse header"
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
        root_directory.reserve(PATH_MAX);

        char absolute_path[PATH_MAX]; 

        // verify absolute path of root directory
        if(!realpath(root_dir.c_str(), absolute_path)){
            std::cerr << "root path error:" <<  std::strerror(errno) << std::endl;
            exit(1);
        }

        root_directory+=absolute_path;

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

        add_route("GET", "/hierarchy", [this](req_context *c) -> std::string& {
            return response_static_file(c, "/hierarchy.html");
        });

        add_route("GET", "/data", [this](req_context *c) -> std::string& {
            Parser json_parser;
            json_parser.parse_file("./Web/menu.txt", buttons);
            json_parser.save_json("./Web/data.json");
            return response_static_file(c, "/data.json");
        });
    }

    void add_route(const std::string& method, const std::string& path, RequestHandler handler) 
    {
        route_handlers[method][path] = handler;
    }

    std::string& response_static_file(req_context *c, const std::string& uri)
    {
        size_t original_length = root_directory.size();

        root_directory += uri;

        std::cout << root_directory << std::endl;

        // get full path
        char abs_path[PATH_MAX];
        if (realpath(root_directory.c_str(), abs_path) == NULL){
            return build_error_response(BadRequest, "Invalid path");
        }

        // Restore rootdirectory to its original size
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
                    std::cerr << "erro sending file:" <<  std::strerror(errno) << std::endl;
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
            .http_resp_add_access_auth("*")
            .http_resp_add_custom_header("Connecton", "close")
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

    /* Try to read one byte at a time until we detect the end */
    while ((rc = readn(c, &ch)) == 1) 
    {
        if (c->total_read >= MAX_REQUEST_SIZE) 
        {
            std::cerr << "Exceeded Maximum request size ! :" << std::endl;
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

    /* EOF before complete request */
    if (rc == 0) 
    {
        /* Real error occurred */
        std::cerr << "EOF received, client may have disconnected : " << std::strerror(errno) << std::endl;
        return READ_REQUEST_ERROR;
    }
    else
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Not ready to read, return incomplete */
            return READ_REQUEST_INCOMPLETE;
        }
        /* Real error occurred */
        std::cerr << "Error occurred while reading : " << std::strerror(errno) << std::endl;
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

// State machine to handle incoming HTTP request
void handleClient(req_context *c) 
{
    if(c->state == READING)
    {
        switch (read_http_request(c))
        {
            case READ_REQUEST_INCOMPLETE:
                c->state = READING;
                // rearm to read again (should be thread safe)
                mod_fd_read(c);
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
                mod_fd_write(c);
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

/*    
     // Handle POST /action
    else if (request_line.find("POST /action HTTP/1.1") != std::string::npos) 
    {
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
*/

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