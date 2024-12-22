# Background

* In UNIX, the `file` is the basic abstraction used for I/O
    * The UNIX `file` abstraction provides a single, consistent interface for common operations for specific resources, thus eliminating much of the complexity of supporting many such resources.
    * Its different from the common usage of the term "file" which is typically associated with persistent data storage.

* For a program to perform input (reading) or output (writing), or both, they must establish a connection or **communications channel** to a `file` by opening it

* The IO `stream` is fairly abstract, high-level concept representing the **communications channel** to a file, device, or process
    * A process references I/O `streams` with the help of descriptors, also known as `file descriptors`.
    * Every process maintains a table of `file descriptors` which it has access to
    * Data transfer happens via a `read` or a `write` system call on a descriptor.
    * all `file descriptors` expose a common generic API that indicates operations that may be performed on the descriptor.
    * The actual implementation of these operations vary by file type and different file types have their own custom implementation. 

* Input (read) operation consists of two stages :
    * waiting for the data to be ready
    * copying the data from the kernel to the process.
* Output (write) operation consists of two stages :
    * Waiting for the process to provide the data
    * Copying the data from the process to the kernel.

* Under UNIX we have multiple I/O models

## 1- Blocking I/O
* If the operation cannot be completed immediately system calls block (doesnt return and is put to sleeping mode) until the operation is complete
* A call to `read` may come when no data is available, but more is expected in the future. Or a process could attempt to `write`, but your device is not ready to accept the data, because your output buffer is full.
* a driver should (by default) block the process, putting it to `sleep` until the request can proceed.
* When a process is put to `sleep`, it is marked as being in a special state and removed from the scheduler’s run queue. Until something comes along to change that state, the process will not be scheduled on any CPU and, therefore, will not run
* Blocking I/O is problematic for a few reasons, a thread might be entirely blocked by a client sending a partial message or by refusing to receive data 

## 2- NonBlocking I/O
* If the operation cannot be completed immediately **do not** put the process in a sleeping mode just return an error.
* Sitting in a loop calling a non blocking operation until its done -called polling- is often a waste of cpu cycles.

## 3- IO Multiplexing
* In applications that must use multiple input or output streams without getting stuck
on any one of them and also doesnt waste cycles polling we can use IO Multiplexing.
* Instead of blocking in every I/O operation, we register all the IO operations we are interested in and instruct the kernel to wait for any one of multiple events to occur and to wake up the process only when one or more of these events occurs or when a specified amount of time has passed.
* So in a way we are blocking a process until any of a given set of file descriptors becomes available for reading or writing but we are waiting simultaneously for several
data streams not blocked in any of them.

Here are several ways of multiplexing I/O on descriptors:

— non-blocking I/O (the descriptor itself is marked as non-blocking, operations may finish partially)
— signal driven I/O (the process owning the descriptor is notified when the I/O state of the descriptor changes)
— polling I/O (with select or poll system calls, both of which provide level triggered notifications about the readiness of descriptors)
---
Signals are expensive to catch, rendering signal driven I/O impractical for cases where a large amount of I/O is performed.
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





Linux has a scalable I/O event notification mechanism called epoll that can monitor a set of file descriptors to see whether there is any I/O ready for them.


With TCP the default port, for an HTTP server on a computer, is port 80. Other ports can also be used, like 8000 or 8080. T

---

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



-- 
epoll stands for event poll and is a Linux specific construct. It allows for a process to monitor multiple file descriptors and get notifications when I/O is possible on them. It allows for both edge-triggered as well as level-triggered notifications.

By default, epoll provides level-triggered notifications. Every call to epoll_wait only returns the subset of file descriptors belonging to the interest list that are ready.

---
* By default, all file descriptors on Unix systems start out in "blocking mode".
    * For instance, if you try to read from a TCP socket then the read call will block until the other side of the connection actually sends data.
* Blocking is a problem for programs that does more than one task at the same time, since blocked processes are suspended.

A file descriptor is put into "nonblocking mode" by adding O_NONBLOCK to the set of fcntl flags on the file descriptor:

non blocking io on its own has a lot of drawbacks
    - waste alot of cpu cycles attempting to read or write
    * hard to manage for alot of ile descriptors

I/O Multiplexing
*  let the kernel know what events (typically read events and write events) are of interest on a set of file descriptors, and then they block until something of interest happens.
- so you block in a single point in your application, whenever anyything happens you wake up handle it and continue waiting

in the epoll system call. This system call has two modes: level-triggered polling, and edge-triggered polling.

Suppose you tell the kernel you're interested in using epoll to monitor read events on some file descriptor. The kernel maintains a list of these interests for each file descriptor. When data comes in on the file descriptor the kernel traverses the interests list and wakes up each process that was blocked in epoll_wait with that file descriptor in the event list.

What I outlined above happens regardless of what triggering mode epoll is in. The difference between level-triggered and edge-triggered polling is what happens in the kernel when you call epoll_wait. In level-triggered mode the kernel will traverse each file descriptor in the interest list to see if it already matches the interest condition. For instance, if you registered a read event on file descriptor 8, when calling epoll_wait the kernel will first check: does file descriptor 8 already have data ready for reading? If any of the file descriptors match the interest then epoll_wait can return without blocking.

By contrast, in edge-triggered mode the kernel skips this check and immediately puts the process to sleep when it calls epoll_wait. This puts all of the responsibility on you, the programmer, to do the Right Thing and fully read and write all data for each file descriptor before waiting on this.

This edge-triggered mode is what makes epoll an O(1) I/O multiplexer: the epoll_wait call will suspend immediately, and since a list is maintained for each file descriptor ahead of time, when new data comes in the kernel immediately knows what processes must be woken up in O(1) time.

To use edge-triggered polling you must put the file descriptors into nonblocking mode. Then you must call read or write until they return EWOULDBLOCK every time. 


--- 
By default, once a file descriptor is added to an epoll interest list using the epoll_ctl()
EPOLL_CTL_ADD operation, it remains active (i.e., subsequent calls to epoll_wait() will
inform us whenever the file descriptor is ready) until we explicitly remove it from
the list using the epoll_ctl() EPOLL_CTL_DEL operation. If we want to be notified only
once about a particular file descriptor, then we can specify the EPOLLONESHOT flag

If this flag is
specified, then, after the next epoll_wait() call that informs us that the corresponding
file descriptor is ready, the file descriptor is marked inactive in the interest list, and
we won’t be informed about its state by future epoll_wait() calls. If desired, we can
subsequently reenable monitoring of this file descriptor using the epoll_ctl()
EPOLL_CTL_MOD operation.

--- 

The refinement is this: an
open file description is removed from the epoll interest list once all file descriptors that
refer to it have been closed. This means that if we create duplicate descriptors refer-
ring to an open file—using dup() (or similar) or fork()—then the open file will be
removed only after the original descriptor and all of the duplicates have been closed.

1.
Make all file descriptors that are to be monitored nonblocking.
2.
Build the epoll interest list using epoll_ctl().
3.
Handle I/O events using the following loop:
a)
Retrieve a list of ready descriptors using epoll_wait().
b)
For each file descriptor that is ready, process I/O until the relevant system
call (e.g., read(), write(), recv(), send(), or accept()) returns with the error EAGAIN
or EWOULDBLOCK.

---

Applications that use nonblocking I/O often use the poll, select, and epoll system
calls as well. poll, select, and epoll have essentially the same functionality: each allow
a process to determine whether it can read from or write to one or more open files
without blocking.
These calls can also block a process until any of a given set of file
descriptors becomes available for reading or writing. Therefore, they are often used
in applications that must use multiple input or output streams without getting stuck
on any one of them.

The epoll
call* was added in 2.5.45 as a way of making the polling function scale to thousands
of file descriptors.

More important, poll
and select are useful, because they let the application wait simultaneously for several
data streams