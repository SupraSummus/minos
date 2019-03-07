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
#include <sched.h>

#include "purge.h"
#include "consts.h"


void * read_all(int fd, size_t * len, size_t * allocated) {
    // first allocate single page
    *allocated = PAGE_SIZE;
    *len = 0;
    void * buf = mmap(
        NULL, *allocated,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0
    );
    if (buf == NULL) return NULL;

    while (true) {
        // read chunk
        ssize_t n = read(
            fd,
            buf + *len,
            *allocated - *len
        );
        if (n == -1) {
            munmap(buf, *allocated);
            return NULL;
        }
        if (n == 0) break;  // we reached an end
        *len += n;
        
        // double allocated space if all is filled
        if (*len == *allocated) { 
            void * new_buf = mremap(buf, *allocated, *allocated * 2, MREMAP_MAYMOVE);
            if (new_buf == MAP_FAILED) {
                munmap(buf, *allocated);
                return NULL;
            }
            buf = new_buf;
            *allocated = *allocated * 2;
        }
    }
    return buf;
}


struct vm_t {
    int id;
    int rfd;
};


int do_cnew (struct vm_t * vm) {
    // read program into local mem
    size_t program_size;
    size_t program_allocated;
    void * program = read_all(vm->rfd, &program_size, &program_allocated);
    if (program == NULL) {
        warn("reading program code failed");
        return -1;
    }
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
            warn("failed to mmap zero-page (check your /proc/sys/vm/mmap_min_addr)");
            munmap(program, program_allocated);
            return -1;
        }

        // copy bootstraping code there and execute it
        memcpy(ENTRY_POINT, purge, PAGE_SIZE);
        ((void (*) (size_t))ENTRY_POINT)(program_size);

        // we shouldn't be here
        assert(false);
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

    // set thread register to start from entrypoint
    if (ptrace(
        PTRACE_POKEUSER, pid,
        offsetof(struct user, regs.rip), 0
    ) == -1) {
        warn("failed to set child's %%RIP to entrypoint");
        return -1;
    }

    // resume execution
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        err(EXIT_FAILURE, "failed second PTRACE_SYSCALL");

    return 0;
}

void handle_syscalls() {
    int alive = 1;

    while (alive > 0) {
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

        // detect killed child
        if (!(siginfo.si_status & 0x80)) {
            alive--;
            fprintf(stderr, "%d killed at %p\n", pid, regs.rip);
            continue;
        }

        bool pass_syscall = false;
        int64_t word;
        switch (syscall) {
            case SYS_mmap:
                // pass only when fd is -1 (we want to prevent real file maps)
                word = ptrace(
                    PTRACE_PEEKUSER, pid,
                    offsetof(struct user, regs.r8), NULL
                );
                pass_syscall = (word == -1);
                break;

            case SYS_clone:
                // check if flags are correct
                word = ptrace(
                    PTRACE_PEEKUSER, pid,
                    offsetof(struct user, regs.rdi), NULL
                );
                pass_syscall = (
                    (word & CLONE_FILES) &&
                    !(word & CLONE_VFORK) &&
                    (word & CLONE_VM)
                );
                break;

            case SYS_write:
            case SYS_read:

            case SYS_mprotect:
            case SYS_munmap:
            case SYS_mremap:

            case SYS_exit:
            case SYS_gettid:
            case SYS_arch_prctl:
            case SYS_futex:
                pass_syscall = true;
                break;

            default:
                pass_syscall = false;
                break;
        }

        if (pass_syscall) {
            /*fprintf(stderr, "%d pass syscall %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                pid,
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);*/
        } else {
            fprintf(stderr, "%d drop syscall %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                pid,
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
                alive --;
                continue;
            } else {
                err(EXIT_FAILURE, "failed to get child registers after syscall");
            }
        }

        /* Print system call result */
        //fprintf(stderr, "syscall result = %ld\n", (long)regs.rax);

        // resume execution
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
    }
}

int main () {
    struct vm_t vm;
    vm.id = 0;
    vm.rfd = STDIN_FILENO;

    do_cnew(&vm);

    handle_syscalls();
}
