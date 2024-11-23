#include <HTTP.h>

std::unordered_map<std::string, std::string> buttons;

/* 
    - The Status-Code element is a 3-digit integer result code 
      of the attempt to understand and satisfy the request. 
    - The Reason-Phrase is intended to give a short textual 
      description of the Status-Code.
 */
status_code_t codes[] = 
{
    /*  1xx: Informational - Not used, but reserved for future use */

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

/*
    media-type = type "/" subtype *( ";" parameter )
    https://www.iana.org/assignments/media-types/media-types.xhtml#example
*/
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

/* 
    Valid HTTP Methods
    HTTP/1.0 : {GET, HEAD, POST}

    - The GET method means retrieve whatever information (in the form of an
      entity) is identified by the Request-URI

    - The HEAD method is identical to GET except that the server must not
      return any Entity-Body in the response. The metainformation contained
      in the HTTP headers in response to a HEAD request should be identical
      to the information sent in response to a GET request.
    - All responses to the HEAD request method must not include a
      body, even though the presence of entity header fields may lead one
      to believe they do.
    - The POST method is used to request that the destination server accept
      the entity enclosed in the request as a new subordinate of the
      resource identified by the Request-URI in the Request-Line.
*/
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


/*
  From W. Richard Stevens - UNIX Network Programming 
  Attempts to Write "n" bytes to a descriptor. 
  Write may actually write less than expected for various reasons (interrupts, ..) 
*/
ssize_t writen(int fd, const void *vptr, ssize_t n)  
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

/* 
    data is read into a buffer (read_buf) in chunks
    and then supplied to the caller one byte at a time 
*/
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


/*

    ██╗  ██╗████████╗████████╗██████╗     ██████╗ ██╗   ██╗██╗██╗     ██████╗ ███████╗██████╗ 
    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔══██╗██║   ██║██║██║     ██╔══██╗██╔════╝██╔══██╗
    ███████║   ██║      ██║   ██████╔╝    ██████╔╝██║   ██║██║██║     ██║  ██║█████╗  ██████╔╝
    ██╔══██║   ██║      ██║   ██╔═══╝     ██╔══██╗██║   ██║██║██║     ██║  ██║██╔══╝  ██╔══██╗
    ██║  ██║   ██║      ██║   ██║         ██████╔╝╚██████╔╝██║███████╗██████╔╝███████╗██║  ██║
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝

 */
HTTPBuilder::HTTPBuilder()
{
    // Reserve data upfront to limit reallocations
    response.reserve(4096); 

    body.reserve(1024);
    body_size.reserve(16);

    date.reserve(64);
    ext.reserve(16);

    headers.reserve(2048);
}

HTTPBuilder& HTTPBuilder::http_resp_add_status(int idx) 
{
    status_code = idx;
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_content_body(std::string_view content) 
{
    body.clear();
    body += content;
    http_resp_add_content_length(body.size());
    return *this;
}

/* 
    - HTTP/1.0 requests containing an entity body 
      must include a valid Content-Length header field.

    - If a request contains an entity body and Content-Length 
      is not specified, the server should send a 400 (bad request) response
 */
HTTPBuilder& HTTPBuilder::http_resp_add_content_length(size_t size) 
{
    body_size.clear();
    body_size += std::to_string(size);

    headers += "Content-Length: ";
    headers += body_size;
    headers += "\r\n";
    return *this;
}

/* 
    - When an Entity-Body is included with a message, the data type of that
      body is determined via the header field Content-Type.

    - Any HTTP/1.0 message containing an entity body should include a
      Content-Type header field defining the media type of that body.

    - HTTP uses Internet Media Types in the Content-Type header field
      in order to provide open and extensible data typing.
 */
HTTPBuilder& HTTPBuilder::http_resp_add_content_type(std::string_view type) 
{
    headers += "Content-Type: ";
    headers += type;
    headers += "\r\n";
    return *this;
}

/* 
    - Get the content type from file extension

    - If the media type remains unknown, the recipient should
      treat it as type "application/octet-stream".
 */
std::string_view HTTPBuilder::http_get_content_type(std::string_view file_path) 
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

/*
    - Content coding values are used to indicate an encoding transformation
      that has been applied to a resource. Content codings are primarily
      used to allow a document to be compressed or encrypted without losing
      the identity of its underlying media type. Typically, the resource is
      stored in this encoding and only decoded before rendering or
      analogous usage.

    - what is more important is that it indicates what decoding 
      mechanism will be required to remove the encoding. 

    - The default for the content encoding is none
 */
HTTPBuilder& HTTPBuilder::http_resp_add_content_encoding(std::string_view encoding) 
{
    headers += "Content-Encoding: ";
    headers += encoding;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_allow(std::string_view methods) 
{
    headers += "Allow: ";
    headers += methods;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_authorization(std::string_view auth) 
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
HTTPBuilder& HTTPBuilder::http_resp_add_date() 
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

HTTPBuilder& HTTPBuilder::http_resp_add_expires(std::string_view expires)
{
    headers += "Expires: ";
    headers += expires;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_last_modified(std::string_view last_modified) 
{
    headers += "Last-Modified: ";
    headers += last_modified;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_location(std::string_view location) 
{
    headers += "Location: ";
    headers += location;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_referer(std::string_view referer) 
{
    headers += "Referer: ";
    headers += referer;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_server(std::string_view server_name) 
{
    headers += "Server: ";
    headers += server_name;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_user_agent(std::string_view user_agent) 
{
    headers += "User-Agent: ";
    headers += user_agent;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_www_auth(std::string_view auth) 
{
    headers += "WWW-Authenticate: ";
    headers += auth;
    headers += "\r\n";
    return *this;
}

HTTPBuilder& HTTPBuilder::http_resp_add_access_auth(std::string_view access_auth) 
{
    headers += "Access-Control-Allow-Origin: ";
    headers += access_auth;
    headers += "\r\n";
    return *this;
}

/*
    Each header field consists of a name followed immediately
    by a colon (":"), a single space (SP) character,
    and the field value.

    HTTP-header = field-name ":" [ field-value ] CRLF
 */
HTTPBuilder& HTTPBuilder::http_resp_add_custom_header(std::string_view key, std::string_view value) 
{
    headers += key;
    headers += ": ";
    headers += value;
    headers += "\r\n";
    return *this;
}

/*
    - Finally build the constructed response header

    Full-Response = Status-Line 
                    *( General-Header | Response-Header | Entity-Header ) 
                    CRLF
                    [ Entity-Body ] 

    - The order in which header fields are received is not significant.
*/
std::string& HTTPBuilder::build() 
{
    response.clear();

    // Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
    response += "HTTP/1.0 ";
    response += std::to_string(codes[status_code].code);
    response += " ";
    response += codes[status_code].reason;
    response += "\r\n";

    /*
        - General-Header = Date | Pragma
        - Response-Header = Location | Server | WWW-Authenticate
        - Entity-Header = Allow | Content-Encoding | Content-Length | Content-Type 
                        | Expires | Last-Modified | extension-header
    */
    response += headers;
    headers.clear();


    // Append body if available (when dynamic response is required i.e not serving a static file)
    response += "\r\n";
    response += body;

    return response;
}

void HTTPBuilder::clear()
{
    body.clear();
    body_size.clear();

    date.clear();
    headers.clear();
}

/* 
    
    ██╗  ██╗████████╗████████╗██████╗     ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗ 
    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
    ███████║   ██║      ██║   ██████╔╝    ██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝
    ██╔══██║   ██║      ██║   ██╔═══╝     ██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗
    ██║  ██║   ██║      ██║   ██║         ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
                                                                                      
 */

HTTPParser::HTTPParser()
{
    method.reserve(16);
    uri.reserve(128); 
    version.reserve(16);

    headers.reserve(32); 

    body.reserve(2048);
}
/*
    A request message from a client to a server includes, within the
    first line of that message :
        1- the method to be applied to the resource
        2- the identifier of the resource
        3- the protocol version in use.

    Full-Request = Request-Line
                   *( General-Header | Request-Header | Entity-Header )
                   CRLF
                   [ Entity-Body ] 
    
    Request-Line = Method SP Request-URI SP HTTP-Version CRLF
    Method = "GET" | "HEAD" | "POST" 
*/
StatusCode HTTPParser::parse_request(const char* req) 
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

    // Extract URI : identifies the resource upon which to apply the request.
    uri += std::string(request_line.substr(first_space + 1, second_space - first_space - 1));

    // Extract version
    version += std::string(request_line.substr(second_space + 1));

    if (version.substr(0, 5) != "HTTP/") {
        return BadRequest; 
    }

    if (version != "HTTP/1.0" && version != "HTTP/1.1") {
        return InternalServerError;  
    }

    size_t headers_end = 0;

    StatusCode headers_status = parse_headers(request.substr(end_of_line + 2), headers_end);  
    if(headers_status != OK){
        return headers_status;
    }

    // Parse the body if its a POST
    if(method == "POST"){
        return parse_body(request, end_of_line + 2 + headers_end);
    }

    return OK;
}

/* 
    Request-Header = Authorization | From | If-Modified-Since | Referer | User-Agent
 */
StatusCode HTTPParser::parse_headers(std::string_view headers_view, size_t& headers_end) 
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
            headers_end = pos + 2;
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

StatusCode HTTPParser::parse_body(std::string_view body_view, size_t body_start) 
{
    std::string_view content_length = get_header("Content-Length");
    if(content_length.empty())
    {
        return BadRequest;
    }

    /* Get length from string_view */
    unsigned long long length;
    auto [ptr, err] = std::from_chars(content_length.data(), content_length.data() + content_length.size(), length);
    if (err == std::errc{} && ptr != content_length.data() + content_length.size()) {
        std::cerr << "Content Length conversion failed " << std::endl;
    }

    // Check given content length aligns with received data
    if(body_view.length() < body_start + length)
    {
        return BadRequest;
    }

    // add the body
    body += body_view.substr(body_start, length);

    return OK;
}

bool HTTPParser::is_method_valid(std::string_view method) 
{
    return std::find(valid_methods.begin(), valid_methods.end(), method) != valid_methods.end();
}

const std::string& HTTPParser::get_method() const 
{ 
    return method; 
}

const std::string& HTTPParser::get_uri() const 
{ 
    return uri; 
}

const std::string& HTTPParser::get_version() const 
{
    return version; 
}
const std::string& HTTPParser::get_body() const 
{
   return body; 
}


// Get specific header value
std::string_view HTTPParser::get_header(std::string_view name) const 
{
    for (size_t i = 0; i < header_count; i++) {
        if (headers[i].first == name) {
            return headers[i].second;
        }
    }
    return {};
}

// Clear all parsed data
void HTTPParser::clear() 
{
    method.clear();
    uri.clear();
    version.clear();
    headers.clear();
    body.clear();
}

/* 
    
    ██╗  ██╗████████╗████████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
    ███████║   ██║      ██║   ██████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
    ██╔══██║   ██║      ██║   ██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ██║  ██║   ██║      ██║   ██║         ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

 */
HTTPServer::HTTPServer(std::string root_dir)
{
    root_directory.reserve(PATH_MAX);

    char absolute_path[PATH_MAX]; 

    /*
        verify absolute path of root directory
        resources are identified relative to this root directory
    */ 
    if(!realpath(root_dir.c_str(), absolute_path)){
        std::cerr << "root path error:" <<  std::strerror(errno) << std::endl;
        exit(1);
    }

    root_directory+=absolute_path;

    setup_default_routes();
}

void HTTPServer::setup_default_routes() 
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

    add_route("POST", "/action", [this](req_context *c) -> std::string& {
        cJSON *json = cJSON_Parse(parser.get_body().c_str());

        if (json) 
        {
            cJSON *actionItem = cJSON_GetObjectItem(json, "action");
            if (actionItem) {
                std::string action = actionItem->valuestring;
                // Log the action for debugging
                std::cout << "Action received: " << action << std::endl;

                // executeCommand(buttons[action]);  
                
                //  Response header

            }
            cJSON_Delete(json);
        }
        builder.clear();
        return builder
        .http_resp_add_status(OK)
        .http_resp_add_access_auth("*")
        .http_resp_add_custom_header("Connecton", "close")
        .build();
    });
}


void HTTPServer::add_route(const std::string& method, const std::string& path, RequestHandler handler) 
{
    route_handlers[method][path] = handler;
}

std::string& HTTPServer::response_static_file(req_context *c, const std::string& uri)
{
    size_t original_length = root_directory.size();

    root_directory += uri;

    // std::cout << root_directory << std::endl;

    // get full path
    char abs_path[PATH_MAX];
    char *res = realpath(root_directory.c_str(), abs_path);

    // Restore rootdirectory to its original size
    root_directory.resize(original_length);

    if (res == NULL){
        return build_error_response(BadRequest, "Invalid path");
    }

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

std::string_view HTTPServer::response_body(int status, const std::string& message)
{
    return builder
        .http_resp_add_status(status)
        .http_resp_add_content_type("text/html")
        .http_resp_add_content_body(
            "<html><body><h1>Error " + std::to_string(status) + "</h1>"
            "<p>" + message + "</p></body></html>")
        .build();
}

void HTTPServer::send_response_header(req_context *c)
{
    /* 
        regular references can only be bound once
     */
    std::reference_wrapper<std::string> response = build_error_response(InternalServerError, "Internal Server Error");

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
                response = build_error_response(NotImplemented, "Method not allowed on resource.");
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
                }else{
                    response = build_error_response(NotImplemented, "Method not allowed on resource.");
                }
                break;
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
            break;
    }

    write_response(c, response);
}

void HTTPServer::write_response(req_context *c , std::string& response)
{
    if(writen(c->connfd, response.c_str(), (ssize_t)response.size())<0){
        std::cerr << "Error while sending the response header" << std::endl;
    }
}

enum write_req_status HTTPServer::send_response_file(req_context *c)
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

std::string& HTTPServer::build_error_response(int status, const std::string& message) 
{
    builder.clear();
    return builder
        .http_resp_add_status(status)
        .http_resp_add_content_type("text/html")
        .http_resp_add_content_body(
            "<html><body><h1>Error " + std::to_string(status) + "</h1>"
            "<p>" + message + "</p></body></html>")
        .build();
}

std::string& HTTPServer::build_success_response(int status, const std::string_view file_path, const size_t file_size) 
{ 
    builder.clear();
    return builder
        .http_resp_add_status(status)
        .http_resp_add_content_type(builder.http_get_content_type(file_path))
        .http_resp_add_content_length(file_size)
        .http_resp_add_access_auth("*")
        .http_resp_add_custom_header("Connecton", "close")
        .build();
}

FILE *HTTPServer::get_file_info(const char* filepath, size_t &size) 
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
/* Read HTTP request until finding double CRLF indicating end of headers */
enum read_req_status HTTPServer::read_http_request(req_context *c)
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
