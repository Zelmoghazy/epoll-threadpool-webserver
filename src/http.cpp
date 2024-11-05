#include <ctime>
#include <string>
#include <iostream>

#include <string>
#include <string_view>
#include <unordered_map>
#include <sstream>


typedef enum StatusCode {
    OK ,
    Created ,
    Accepted ,
    NoContent ,
    MovedPermanently ,
    MovedTemporarily ,
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

/* 
    The Status-Code element is a 3-digit integer result code of the
    attempt to understand and satisfy the request. The Reason-Phrase is
    intended to give a short textual description of the Status-Code.
 */

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



class HTTPBuilder 
{
private:
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    int status_code = 0;
    using Handler = std::function<void()>;
    std::unordered_map<std::string, Handler> routes;

public:
    HTTPBuilder& http_resp_add_status(StatusCode idx) {
        status_code = idx;
        return *this;
    }

    HTTPBuilder& http_resp_add_content_length(size_t size) {
        headers["Content-Length"] = std::to_string(size);
        return *this;
    }

    HTTPBuilder& http_resp_add_content_body(const std::string& content) {
        body = content;
        http_resp_add_content_length(body.size());
        return *this;
    }

    HTTPBuilder& http_resp_add_content_type(const std::string& type) {
        headers["Content-Type"] = type;
        return *this;
    }

    std::string get_content_type(const std::string& file_path) 
    {
        // Simple content type detection based on file extension
        if (file_path.ends_with(".html")) return "text/html";
        if (file_path.ends_with(".css")) return "text/css";
        if (file_path.ends_with(".js")) return "application/javascript";
        if (file_path.ends_with(".jpg") || file_path.ends_with(".jpeg")) return "image/jpeg";
        if (file_path.ends_with(".png")) return "image/png";
        return "application/octet-stream";
    }

    HTTPBuilder& http_resp_add_content_encoding(const std::string& encoding) {
        headers["Content-Encoding"] = encoding;
        return *this;
    }

    HTTPBuilder& http_resp_add_allow(const std::string& methods) {
        headers["Allow"] = methods;
        return *this;
    }

    HTTPBuilder& http_resp_add_authorization(const std::string& auth) {
        headers["Authorization"] = auth;
        return *this;
    }

    HTTPBuilder& http_resp_add_date() {
        std::time_t now = std::time(nullptr);
        char buf[100];
        if (std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now))) {
            headers["Date"] = buf;
        }
        return *this;
    }

    HTTPBuilder& http_resp_add_expires(const std::string& expires) {
        headers["Expires"] = expires;
        return *this;
    }

    HTTPBuilder& http_resp_add_last_modified(const std::string& last_modified) {
        headers["Last-Modified"] = last_modified;
        return *this;
    }

    HTTPBuilder& http_resp_add_location(const std::string& location) {
        headers["Location"] = location;
        return *this;
    }

    HTTPBuilder& http_resp_add_referer(const std::string& referer) {
        headers["Referer"] = referer;
        return *this;
    }

    HTTPBuilder& http_resp_add_server(const std::string& server_name) {
        headers["Server"] = server_name;
        return *this;
    }

    HTTPBuilder& http_resp_add_user_agent(const std::string& user_agent) {
        headers["User-Agent"] = user_agent;
        return *this;
    }

    HTTPBuilder& http_resp_add_www_auth(const std::string& auth) {
        headers["WWW-Authenticate"] = auth;
        return *this;
    }

    HTTPBuilder& http_resp_add_access_auth(const std::string& access_auth) {
        headers["Access-Control-Allow-Origin"] = access_auth;
        return *this;
    }

    HTTPBuilder& http_resp_add_custom_header(const std::string& key, const std::string& value) {
        headers[key] = value;
        return *this;
    }

    std::string build() const 
    {
        size_t estimated_size = 50;     
        estimated_size += body.size();  

        // Include headers sizes
        for (const auto& header : headers) {
            estimated_size += header.first.size() + header.second.size() + 4; 
        }

        std::string response;
        response.reserve(estimated_size);

        // Build status line
        response += "HTTP/1.0 ";
        response += std::to_string(codes[status_code].code);
        response += " ";
        response += codes[status_code].reason;
        response += "\r\n";

        for (const auto& header : headers) {
            response += header.first + ": " + header.second + "\r\n";
        }

        response += "\r\n";
        response += body;

        return response;
    }

    /*
    HTTPBuilder builder;
    std::string response = builder
        .http_resp_add_status(200)
        .http_resp_add_content_type("text/html")
        .http_resp_add_content_body("<html><body>Hello, World!</body></html>")
        .build();
        std::cout << response;
     */
};

class HTTPParser 
{
private:
    std::string method;
    std::string uri;
    std::string version;
    std::unordered_map<std::string, std::string> headers;

public:

    /*
        A request message from a client to a server includes, within the
        first line of that message :
            1- the method to be applied to the resource
            2- the identifier of the resource
            3- the protocol version in use.
     */
    int parse_request(const char* req) 
    {
        std::string_view request(req);  // no copying (I think ?)

        /* ------------------ Request line ------------------ */ 
        auto end_of_line = request.find("\r\n");
        if (end_of_line == std::string_view::npos) {
            return BadRequest; // Invalid request, no newline
        }

        std::string_view request_line = request.substr(0, end_of_line);

        // Extract method
        auto first_space = request_line.find(' ');
        if (first_space == std::string_view::npos){
            return BadRequest; 
        } 
        method = std::string(request_line.substr(0, first_space));

        // Extract URI
        auto second_space = request_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos) {
            return BadRequest; 
        }
        uri = std::string(request_line.substr(first_space + 1, second_space - first_space - 1));

        // Extract version
        version = std::string(request_line.substr(second_space + 1));

        if (version.substr(0, 5) != "HTTP/") {
            return BadRequest; 
        }

        if (version != "HTTP/1.0" && version != "HTTP/1.1") {
            return InternalServerError;  
        }
        // Parse rest of headers
        if (!parseHeaders(request.substr(end_of_line + 2))) {
            return BadRequest;  // Bad Request, error in headers
        }

        return OK;  
    }

    void parseHeaders(std::string_view headers_view) 
    {
        size_t pos = 0;

        while (pos < headers_view.size()) 
        {
            // Find end of the current line
            auto end_of_line = headers_view.find("\r\n", pos);
            if (end_of_line == std::string_view::npos){
                break;
            } 

            // Get the header line
            std::string_view line = headers_view.substr(pos, end_of_line - pos);
            pos = end_of_line + 2;

            if (line.empty()) {
                break;
            }

            auto colon_pos = line.find(':');
            if (colon_pos == std::string_view::npos){
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
    // Getters
    const std::string& get_method()     const { return method; }
    const std::string& get_uri()        const { return uri; }
    const std::string& get_version()    const { return version; }
    const std::unordered_map<std::string, std::string>& get_headers() const { return headers; }
    
    // Get specific header value
    std::string get_header(const std::string& key) const 
    {
        auto it = headers.find(key);
        return (it != headers.end()) ? it->second : "";
    }

    // Clear all parsed data
    void clear() {
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
            // dont care to handle for now
            std::cerr << "root path error" << std::endl;
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

    void send_response_header(const char* req)
    {
        std::string response;

        switch(parser.parse_request(req))
        {
            case OK:
                std::string method = parser.get_method();
                std::string uri    = parser.get_uri();

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
                if (method_routes.find(uri) == method_routes.end()) {
                    if (method == "GET") {
                        std::string file_path = root_directory + "/" + filename;
                        // Do one more check to make sure everything is fine
                        if(!file_path_check(file_path)){
                            response = build_error_response(BAD_REQUEST, "Invalid path");
                        }

                        size_t file_size;

                        FILE *file = get_file_info(file_path, file_size);

                        if(!file)
                            response = build_error_response(NOT_FOUND, "Resource not found");
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

        if(writen(connfd,response.c_str(),response.size())<0){
            std:cerr << "Error while sending the response header" << std::endl;
        }
    }

    int send_response_file(int connfd, FILE *file)
    {
        fseek(file, 0L, SEEK_END);
        __off_t file_size = ftell(file);
        fseek(file, 0L, SEEK_SET);

        size_t readn;

        int filefd = fileno(file);

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

    bool file_path_check(const std::string& file_path) {
        char abs_path[PATH_MAX];

        if (realpath(file_path.c_str(), abs_path) == nullptr) {
            return false;
        }

        if (strncmp(root_directory.c_str(), abs_path, root_directory.length()) != 0) {
            return false;
        }

        return true;
    }

    std::string build_error_response(int status, const std::string& message) {
        return builder
            .http_resp_add_status(status)
            .http_resp_add_content_type("text/html")
            .http_resp_add_content_body(
                "<html><body><h1>Error " + std::to_string(status) + "</h1>"
                "<p>" + message + "</p></body></html>")
            .build();
    }

   std::string build_success_response(int status, const std::string& message, const std::string& file_path) {
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

    std::string serve_file(const std::string& filename) 
    {
        std::string file_path = root_directory + "/" + filename;
        return read_file(file_path);
    }
}


/* Media Types */

// https://www.iana.org/assignments/media-types/media-types.xhtml#example
typedef struct media_types{
    const char* name;
    const char* type;
}media_types;

// alot of types I will add to it when needed
media_types types[] = {
    {"json",                "application/json"},
    {"pdf",                 "application/pdf"},
    {"ttf",                 "font/ttf"},
    {"woff",                "font/woff"},
    {"gif",                 "image/gif"},
    {"jpeg",                "image/jpeg"},
    {"png",	                "image/png"},
    {"webp",                "image/webp"},
    {"svg+xml",             "image/svg+xml"},
    {"vnd.microsoft.icon",  "image/vnd.microsoft.icon"},
    {"csv",	                "text/csv"},
    {"html",                "text/html" },
    {"css",	                "text/css"},
    {"javascript"	        "text/javascript"},
    {"markdown"	            "text/markdown"},
    {"plain"	            "text/plain"},
    {"mp4"	                "video/mp4"},
};

/* Product Tokens */

// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36



/* Full-Response = Status-Line ; Section 6.1
*( General-Header ; Section 4.3
| Response-Header ; Section 6.2
| Entity-Header ) ; Section 7.1
CRLF
[ Entity-Body ] ; Section 7.2 


Example:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Length: 0
Connection: close


is the Status-Line,
consisting of the protocol version followed by a numeric status code
and its associated textual phrase, with each element separated by SP
characters.

The response header fields allow the server to pass additional
information about the response which cannot be placed in the Status-
Line. These header fields give information about the server and about
further access to the resource identified by the Request-URI.


Entity-Header fields define optional metainformation about the
Entity-Body or, if no body is present, about the resource identified
by the request.
Entity-Header = Allow ; Section 10.1
| Content-Encoding ; Section 10.3
| Content-Length ; Section 10.4
| Content-Type ; Section 10.5
| Expires ; Section 10.7
| Last-Modified ; Section 10.10
| extension-header


*/



/*
    The Request-Line begins with a method token, followed by the
    Request-URI and the protocol version, and ending with CRLF.
    The method is case-sensitive.
 */
