#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/limits.h>

#define STACK_SIZE      (8 * 1024 * 1024)  // 8MB stack
#define MAX_EVENTS      10
#define MAX_PROCESSES   16
#define SPLICE_SIZE     (64 * 1024)  // 64KB chunks

struct process_info {
    pid_t pid;
    int stdout_fd;
    int output_fd;
    char *cmd;
    int exit_code;
    volatile int active;
};

struct monitor_context {
    int epoll_fd;
    int signal_fd;
    int exit_fd;
    struct process_info processes[MAX_PROCESSES];
    int process_count;
};

static int make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Function to start a child process using clone()
static int start_child_process(void *arg) {
    struct process_info *proc = (struct process_info *)arg;
    
    // Close the read end of stdout pipe
    close(proc->stdout_fd);
    
    // Duplicate the write end to stdout
    dup2(proc->output_fd, STDOUT_FILENO);
    close(proc->output_fd);
    
    // Execute the command
    execl("/bin/sh", "sh", "-c", proc->cmd, NULL);
    _exit(EXIT_FAILURE);
}

static int setup_signal_fd() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        return -1;
    }
    
    return signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
}

// Initialize the monitoring system
static struct monitor_context *init_monitor(void) {
    struct monitor_context *ctx = calloc(1, sizeof(struct monitor_context));
    if (!ctx) return NULL;

    // Create epoll instance
    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd == -1) goto error;

    // Create eventfd for clean shutdown
    ctx->exit_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->exit_fd == -1) goto error;

    // Setup signal handling
    ctx->signal_fd = setup_signal_fd();
    if (ctx->signal_fd == -1) goto error;

    // Add signal_fd and exit_fd to epoll
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = ctx->signal_fd
    };
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->signal_fd, &ev) == -1) goto error;

    ev.data.fd = ctx->exit_fd;
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->exit_fd, &ev) == -1) goto error;

    return ctx;

error:
    if (ctx->epoll_fd != -1) close(ctx->epoll_fd);
    if (ctx->exit_fd != -1) close(ctx->exit_fd);
    if (ctx->signal_fd != -1) close(ctx->signal_fd);
    free(ctx);
    return NULL;
}

static int start_process(struct monitor_context *ctx, const char *command, const char *output_path) {
    if (ctx->process_count >= MAX_PROCESSES) return -1;

    int process_idx = ctx->process_count;
    struct process_info *proc = &ctx->processes[process_idx];

    // Create pipe for stdout
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) == -1) return -1;

    // Open output file
    proc->output_fd = open(output_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (proc->output_fd == -1) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }

    // Make read end non-blocking
    if (make_nonblocking(pipe_fds[0]) == -1) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(proc->output_fd);
        return -1;
    }

    // Allocate stack for child process
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(proc->output_fd);
        return -1;
    }

    // Setup process info
    proc->stdout_fd = pipe_fds[0];
    proc->cmd = strdup(command);
    proc->active = 1;
    proc->exit_code = -1;

    // Create child process using clone
    int clone_flags = CLONE_VM | CLONE_FILES | SIGCHLD;
    pid_t pid = clone(start_child_process, stack + STACK_SIZE, 
                     clone_flags, proc);
    
    if (pid == -1) {
        free(stack);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(proc->output_fd);
        free(proc->cmd);
        return -1;
    }

    proc->pid = pid;

    // Add stdout to epoll
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.ptr = proc
    };
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, proc->stdout_fd, &ev) == -1) {
        kill(pid, SIGKILL);
        free(stack);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(proc->output_fd);
        free(proc->cmd);
        return -1;
    }

    ctx->process_count++;
    return process_idx;
}

static void handle_process_output(struct process_info *proc) {
    // Use splice to efficiently copy data from pipe to file
    while (1) {
        ssize_t bytes = splice(proc->stdout_fd, NULL, proc->output_fd, NULL,
                             SPLICE_SIZE, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        
        if (bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // No more data available
            }
            perror("splice");
            break;
        }
        if (bytes == 0) {
            // EOF - process has closed its stdout
            proc->active = 0;
            break;
        }
    }
}

static void handle_signal(struct monitor_context *ctx) {
    struct signalfd_siginfo si;
    ssize_t bytes = read(ctx->signal_fd, &si, sizeof(si));
    
    if (bytes != sizeof(si)) return;

    if (si.ssi_signo == SIGCHLD) {
        // Handle child process termination
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            for (int i = 0; i < ctx->process_count; i++) {
                if (ctx->processes[i].pid == pid) {
                    ctx->processes[i].exit_code = WEXITSTATUS(status);
                    ctx->processes[i].active = 0;
                    break;
                }
            }
        }
    }
}

static void monitor_loop(struct monitor_context *ctx) {
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == ctx->signal_fd) {
                handle_signal(ctx);
                continue;
            }
            
            if (events[i].data.fd == ctx->exit_fd) {
                return;  // Clean shutdown requested
            }

            struct process_info *proc = events[i].data.ptr;
            if (events[i].events & EPOLLIN) {
                handle_process_output(proc);
            }
        }
    }
}

static void cleanup_monitor(struct monitor_context *ctx) {
    // Kill all active processes
    for (int i = 0; i < ctx->process_count; i++) {
        if (ctx->processes[i].active) {
            kill(ctx->processes[i].pid, SIGTERM);
            close(ctx->processes[i].stdout_fd);
            close(ctx->processes[i].output_fd);
            free(ctx->processes[i].cmd);
        }
    }

    close(ctx->epoll_fd);
    close(ctx->signal_fd);
    close(ctx->exit_fd);
    free(ctx);
}

int main() 
{
    // Initialize the monitor
    struct monitor_context *ctx = init_monitor();
    if (!ctx) {
        fprintf(stderr, "Failed to initialize monitor\n");
        return 1;
    }

    // Start some processes
    int proc_id = start_process(ctx, "ls -la", "/tmp/ls_output.txt");
    if (proc_id < 0) {
        fprintf(stderr, "Failed to start process\n");
        cleanup_monitor(ctx);
        return 1;
    }

    // Run the monitor loop
    monitor_loop(ctx);

    // Clean up
    cleanup_monitor(ctx);
    return 0;
}