#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "purge.h"
#include "consts.h"


void * read_all(int fd, size_t * len, size_t * allocated) {
    *allocated = PAGE_SIZE;
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


struct vm_t {
    int id;
    int rfd;
    struct th_t * halted_threads;
    struct th_t * threads;
};


struct th_t {
    int id;
    pid_t pid;
    struct th_t * next;
};


int do_vmnew (struct vm_t * vm) {
    assert(vm->threads == NULL);
    assert(vm->halted_threads == NULL);

    // read program into local mem
    size_t program_size;
    size_t program_allocated;
    void * program = read_all(vm->rfd, &program_size, &program_allocated);
    close(vm->rfd);
    vm->rfd = -1;
    program_size = (program_size / PAGE_SIZE + 1) * PAGE_SIZE;  // TODO better rounding
    fprintf(stderr, "program loaded locally at %p, len %zu\n", program, program_size);

    // make child
    pid_t pid = fork();
    if (pid < 0) {
        warn("initial fork failed");
        return -1;
    }

    if (pid == 0) { /* child */
        // alloc zero-page
        if (mmap(
            ENTRY_POINT, PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0
        ) == MAP_FAILED) {
            err(EXIT_FAILURE, "failed to mmap zero-page (check your /proc/sys/vm/mmap_min_addr)");
        }

        // copy bootstraping code there and execute it
        memcpy(ENTRY_POINT, purge, PAGE_SIZE);
        ((void (*) (size_t))ENTRY_POINT)(program_size);

        errx(EXIT_FAILURE, "we shouldn't be here, oopsie");
    }

    /* parent is a tracer */
    fprintf(stderr, "child pid = %d\n", pid);
    waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    fprintf(stderr, "got child traced\n");

    // copy code into child memory
    struct iovec local_io;
    local_io.iov_base = program;
    local_io.iov_len = program_size;
    struct iovec remote_io;
    remote_io.iov_base = ENTRY_POINT;
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

    // release parent code memory
    munmap(program, program_allocated);

    // append halted thread info
    struct th_t * th = malloc(sizeof(struct th_t));
    th->id = -1;
    th->pid = pid;
    th->next = vm->halted_threads;
    vm->halted_threads = th;

    return 0;
}

int do_thnew(struct vm_t * vm) {
    if (vm->halted_threads == NULL) {
        warnx("multiple threads are unsupported yet");
        return -1;
    }
    struct th_t * th = vm->halted_threads;
    th->id = 0;
    vm->halted_threads = th->next;
    th->next = vm->threads;
    vm->threads = th;

    // set thread register to start from entrypoint
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, th->pid, NULL, &regs) == -1) {
        err(EXIT_FAILURE, "failed to get child registers");
    }
    regs.rip = ENTRY_POINT;
    if (ptrace(PTRACE_SETREGS, th->pid, NULL, &regs) == -1) {
        err(EXIT_FAILURE, "failed to set child registers");
    }

    // resume execution
    if (ptrace(PTRACE_SYSCALL, th->pid, 0, 0) == -1)
        err(EXIT_FAILURE, "failed second PTRACE_SYSCALL");

    return 0;
}

int main () {
    struct vm_t vm;
    vm.id = 0;
    vm.rfd = STDIN_FILENO;
    vm.threads = NULL;
    vm.halted_threads = NULL;

    do_vmnew(&vm);
    do_thnew(&vm);

    for (int i = 0; i < 10; i ++) {
        siginfo_t siginfo;

        /* wait for next system call */
        if (waitid(P_ALL, 0, &siginfo, WSTOPPED) == -1)
            err(EXIT_FAILURE, "wait for child syscall failed");

        pid_t pid = siginfo.si_pid;

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            err(EXIT_FAILURE, "failed to get child registers");
        long syscall = regs.orig_rax;

        bool pass_syscall = false;
        switch (syscall) {
            case SYS_write:
            case SYS_read:
            case SYS_exit:
            case SYS_mmap:
            case SYS_gettid:
                pass_syscall = true;
                break;
            default:
                pass_syscall = false;
                break;
        }

        if (pass_syscall) {
            fprintf(stderr, "syscall pass %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);
        } else {
            fprintf(stderr, "syscall drop %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);
            regs.orig_rax = -1; // set to invalid syscall
            ptrace(PTRACE_SETREGS, pid, 0, &regs);
        }

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed second PTRACE_SYSCALL");
        if (waitpid(pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed to wait for second PTRACE_SYSCALL");

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            if (errno == ESRCH) {
                // system call was _exit(2) or similar
                fprintf(stderr, "child exited with code %llu\n", regs.rdi);
                exit(regs.rdi);
            }
            err(EXIT_FAILURE, "failed to get child registers after syscall");
        }

        /* Print system call result */
        fprintf(stderr, "syscall result = %ld\n", (long)regs.rax);

        // resume execution
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
    }
}
