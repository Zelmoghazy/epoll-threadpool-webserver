
With TCP the default port, for an HTTP server on a computer, is port 80. Other ports can also be used, like 8000 or 8080. T

The browser is always the entity initiating the request.

To display a Web page, the browser sends an original request to fetch the HTML document that represents the page. It then parses this file, making additional requests corresponding to execution scripts, layout information (CSS) to display, and sub-resources contained within the page (usually images and videos). The Web browser then combines these resources to present the complete document, the Web page. Scripts executed by the browser can fetch more resources in later phases and the browser updates the Web page accordingly.


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
