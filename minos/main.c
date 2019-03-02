#define _GNU_SOURCE

#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/uio.h>

/* C standard library */

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include "purge.h"

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

void * read_all(int fd, size_t * len, size_t * allocated) {
    *allocated = sysconf(_SC_PAGESIZE);
    *len = 0;
    void * buf = mmap(
        NULL, *allocated,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0
    );
    while (true) {
        ssize_t n = read(
            fd,
            buf + *len,
            *allocated - *len
        );
        if (n == -1) err(EXIT_FAILURE, "failed to read program code");
        if (n == 0) break;
        *len += n;
        if (*len == *allocated) { // double allocated space
            buf = mremap(buf, *allocated, *allocated * 2, MREMAP_MAYMOVE);
            *allocated = *allocated * 2;
        }
    }
    return buf;
}

int main () {
    long page_size = sysconf(_SC_PAGESIZE);

    // read program into local mem
    size_t program_size;
    size_t program_allocated;
    void * program = read_all(STDIN_FILENO, &program_size, &program_allocated);
    program_size = (program_size / page_size + 1) * page_size;  // TODO better rounding
    fprintf(stderr, "program loaded locally at %p, len %zu\n", program, program_size);

    // make child
    pid_t pid = fork();
    if (pid < 0) {
        err(EXIT_FAILURE, "initial fork failed");
    }

    if (pid == 0) { /* child */
        // alloc zero-page
        if (mmap(
            (void *)0, page_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0
        ) == MAP_FAILED) {
            err(EXIT_FAILURE, "failed to mmap zero-page (check your /proc/sys/vm/mmap_min_addr)");
        }

        // copy bootstraping code there and execute it
        memcpy((void *)0, purge, 0x1000);
        ((void (*)(size_t))0)(program_size);

        errx(EXIT_FAILURE, "we shouldn't be here, oopsie");
    }

    /* parent is a tracer */
    fprintf(stderr, "child pid = %d\n", pid);
    waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    fprintf(stderr, "got child traced\n");

    // copy code into child memory
    struct iovec local_io;
    local_io.iov_base = program;
    local_io.iov_len = program_size;
    struct iovec remote_io;
    remote_io.iov_base = (void *)0;
    remote_io.iov_len = program_size;
    if (process_vm_writev(
        pid,
        &local_io, 1,
        &remote_io, 1,
        0
    ) != (ssize_t)program_size) {
        err(EXIT_FAILURE, "failed to copy program to child");
    }
    fprintf(stderr, "program copied to child\n");

    // resume child execution
    fprintf(stderr, "resuming child execution\n");
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        err(EXIT_FAILURE, "failed to get child registers");
    }
    regs.rip = 0;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        err(EXIT_FAILURE, "failed to set child registers");
    }

    for (int i = 0; i < 10; i ++) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));
        long syscall = regs.orig_rax;

        /* Print a representation of the system call */
        fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        fprintf(stderr, " = %ld\n", (long)regs.rax);
    }
}
