

Linux has a scalable I/O event notification mechanism called epoll that can monitor a set
of file descriptors to see whether there is any I/O ready for them.


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

receiving data in partial as above is a rare case, but in busy networks with some custom configs you will face such a case.

but the problem is not parsing headers, its all about you have to do everything in partial as your data is ready partially. so you need to store states of the place you previously were in, for any connection.

so when you are doing non-blocking IO, no matter you are doing all things in one thread or pass to other threads to do stuffs, anyway you are lost in lots of partially done stuffs.

so you need to properly store states of anything, yes anything. and continue from that state. and that makes your code more complicated as the problem is complicated.

--- 


### Port Number
At any given time, multiple processes can use either UDP or TCP. Both TCP and UDP
use 16-bit integer port numbers to differentiate between these processes.
When a client wants to contact a server, the client must identify the server with
which it wants to communicate. Both TCP and UDP define a group of well-kncnun ports
to identify well-known services. For example, every TCP / IP implementation that sup-
ports FTP assigns the well-known port of 21 (decimal) to the FTP server. TFTP servers,
for the Trivial File Transfer Protocol, are assigned the UDP port of 69.

he port numbers are divided into three ranges:
1. The well-known ports: 0 through 1023. These port numbers are controlled and
assigned by the IANA. When possible, the same port is assigned to a given ser-
vice for both TCP and UDP. For example, port 80 is assigned for a Web server,
for both protocols, even though all implementations currently use only TCP.
2. The registered ports: 1024 through 49151 . These are not controlled by the lANA,
but the IANA registers and lists the uses of these ports as a convenience to the
community. When possible, the same port is assigned to a given service for
both TCP and UDP. For example, ports 6000 through 6063 are assigned for an X
Window server, for both protocols, even though all implementations currently
use only TCP. The upper limit of 49151 for these ports is new, as RFC 1700 [Rey-
nolds and Postel 1994) lists the upper range as 65535.
3. The dynamic or private ports, 49152 through 65535. The IANA says nothing
about these ports. These are what we call ephemeral ports.


### Socket Pair
The socket pair for a TCP connection is the 4-tuple that defines the two endpoints of the
connection: the local IP address, local TCP port, foreign IP address, and foreign TCP
port. A socket pair uniquely identifies every TCP connection on an internet.
The two values that identify each endpoint, an IP address and a port number, are
often called a socket.

--- 
## Background
* In UNIX, the file is the basic abstraction used for I/O
    *  The UNIX file abstraction provides a single, consistent interface for these operations, thus eliminating much of the complexity of supporting many such resources.
    * different from the common usage of the term “file,” which is typically associated with persistent data storage.
* For a program to perform input (reading) or output (writing), or both, they must establish a connection or communications channel to a file by opening it
* an IO stream is fairly abstract, high-level concept representing a communications channel to a file, device, or process
* A process references I/O streams with the help of descriptors, also known as file descriptors.
* Data transfer happens via a read or a write system call on a descriptor.
* all file descriptors expose a common generic API that indicates operations hat may be performed on the descriptor.
* The actual implementation of these operations vary by file type and different file types have their own custom implementation. 

* Every process maintains a table of file descriptors which it has access to

* Under UNIX we have multiple I/O models
* Input operation consists of two stages :
    * waiting for the data to be ready
    * copying the data from the kernel to the process.
* Output operation consists of two stages :
    * Waiting for the process to provide the data
    * Copying the data from the process to the kernel.

1- Blocking I/O
* If the operation cannot be completed immediately system calls block (doesnt return and is put to sleeping mode) until the operation is complete
* Blocking I/O is problematic for a few reasons, a thread might be entirely blocked by a client sending a partial message or by refusing to receive data 
2- NonBlocking I/O
* If the operation cannot be completed immediately do not put the process in a sleeping mode just return an error
* polling is sitting in a loop calling a non blocking operation until its done, its often a waste of cpu cycles

3- IO Multiplexing
* Instead of blocking in every I/O operation, we register all the IO operations we are interested in and instruct the kernel to wait for any one of multiple events to occur and to wake up the process only when one or more of these events occurs or when a specified amount of time has passed.

here are several ways of multiplexing I/O on descriptors:

— non-blocking I/O (the descriptor itself is marked as non-blocking, operations may finish partially)
— signal driven I/O (the process owning the descriptor is notified when the I/O state of the descriptor changes)
— polling I/O (with select or poll system calls, both of which provide level triggered notifications about the readiness of descriptors)


---
ignals are expensive to catch, rendering signal driven I/O impractical for cases where a large amount of I/O is performed.
It is typically used for “exceptional conditions” 

---


* Most networking is done using sockets. A socket is referenced by a descriptor and acts as an endpoint for communication. Two processes can create two sockets each and establish a reliable byte stream by connecting those two end points. Once the connection has been established, the descriptors can be read from or written to using the file offsets described above.

* By default, sockets are blocking. This means that when we issue a socket call that can-
not be completed immediately, our process is put to sleep, waiting for the condition to
be true. 

A descriptor is considered ready if a process can perform an I/O operation on the descriptor without blocking.

There are two ways to find out about the readiness status of a descriptor — edge triggered and level-triggered.

## I/O Strategies

Since even with edge-triggered epoll, multiple events can be generated upon receipt of multiple chunks of data, the caller has the option to specify the EPOLLONESHOT flag, to tell epoll to disable the associated file descriptor after the receipt of an event with epoll_wait(2)

 An event-
       driven state machine application should, after having received
       EAGAIN, record its current state so that at the next call to
       do_use_fd() it will continue to read(2) or write(2) from where it
       stopped before.

level triggered
    To determine if a descriptor is ready, the process tries to perform a non blocking I/O operation.

    Edge Triggered
The process receives a notification only when the file descriptor is “ready” (usually when there is any new activity on the file descriptor since it was last monitored).

Readiness change notification (or edge-triggered readiness notification) means you give the kernel a file descriptor, and later, when that descriptor transitions from not ready to ready, the kernel notifies you somehow. It then assumes you know the file descriptor is ready, and will not send any more readiness notifications of that type for that file descriptor until you do something that causes the file descriptor to no longer be ready (e.g. until you receive the EWOULDBLOCK error on a send, recv, or accept call, or a send or recv transfers less than the requested number of bytes).


Thus, a process is only armed with incomplete data as it tries to perform any subsequent I/O operation. To work around this, the process can attempt to perform the maximum amount of I/O it possibly can every time it gets a descriptor readiness notification, since failing to do this would mean the process would have to wait until the next notification arrives, even if I/O is possible on a descriptor before the arrival of the next notification.

-- 
epoll stands for event poll and is a Linux specific construct. It allows for a process to monitor multiple file descriptors and get notifications when I/O is possible on them. It allows for both edge-triggered as well as level-triggered notifications.

By default, epoll provides level-triggered notifications. Every call to epoll_wait only returns the subset of file descriptors belonging to the interest list that are ready.