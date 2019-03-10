#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

#include <minos.h>

#include "purge.h"
#include "consts.h"
#include "thread.h"


static const bool DEBUG = false;


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


bool set_ptrace_options(pid_t pid) {
    if (ptrace(
        PTRACE_SETOPTIONS, pid, 0,
        PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT
    ) != 0) {
        warn("failed PTRACE_SETOPTIONS");
        return false;
    } else {
        return true;
    }
}


bool do_cnew (struct c_t * c, int rfd) {
    assert(c->threads == NULL);
    assert(c->thread_count == 0);

    // read program into local mem
    size_t program_size;
    size_t program_allocated;
    void * program = read_all(rfd, &program_size, &program_allocated);
    if (program == NULL) {
        warn("reading program code failed");
        return false;
    }
    close(rfd);
    program_size = (program_size / PAGE_SIZE + 1) * PAGE_SIZE;  // TODO better rounding
    if (DEBUG) fprintf(stderr, "program loaded locally at %p, len %zu\n", program, program_size);

    // make child
    pid_t pid = fork();
    if (pid < 0) {
        warn("initial fork failed");
        munmap(program, program_allocated);
        return false;
    }

    if (pid == 0) { /* child */
        // space for boostraping code
        if (mmap(
            (void *)ENTRY_POINT, PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0
        ) == MAP_FAILED) {
            err(
                EXIT_FAILURE,
                "failed to mmap page at %p (check your /proc/sys/vm/mmap_min_addr)",
                (void *)ENTRY_POINT
            );
            return false;
        }

        // copy bootstraping code there and execute it
        memcpy((void *)ENTRY_POINT, purge, PAGE_SIZE);
        if (DEBUG) fprintf(stderr, "executing bootstraping code copied to %p\n", (void *)ENTRY_POINT);
        ((void (*) (size_t))ENTRY_POINT)(program_size);

        // we shouldn't be here
        assert(false);
    }

    /* parent is a tracer */
    if (DEBUG) fprintf(stderr, "child pid = %d\n", pid);
    if (
        (waitpid(pid, 0, 0) == -1) |  // sync with PTRACE_TRACEME
        !set_ptrace_options(pid)
    ) {
        kill(pid, SIGKILL);
        munmap(program, program_allocated);
        return false;
    }
    if (DEBUG) fprintf(stderr, "got child traced\n");

    // copy code into child memory
    struct iovec local_io;
    local_io.iov_base = program;
    local_io.iov_len = program_size;
    struct iovec remote_io;
    remote_io.iov_base = (void *)ENTRY_POINT;
    remote_io.iov_len = program_size;
    if (process_vm_writev(
        pid,
        &local_io, 1,
        &remote_io, 1,
        0
    ) != (ssize_t)program_size) {
        warn("failed to copy program to child");
        kill(pid, SIGKILL);
        munmap(program, program_allocated);
        return false;
    }
    if (DEBUG) fprintf(stderr, "program copied to child\n");

    // release parent code memory
    munmap(program, program_allocated);

    // set thread register to start from entrypoint
    if (ptrace(
        PTRACE_POKEUSER, pid,
        offsetof(struct user, regs.rip), ENTRY_POINT
    ) == -1) {
        warn("failed to set child's %%RIP to entrypoint");
        kill(pid, SIGKILL);
        return false;
    }

    // register thread in the list
    struct th_t * th = malloc(sizeof(struct th_t));
    if (th == NULL) {
        kill(pid, SIGKILL);
        return false;
    }
    th_init(th);
    th->tid = pid;
    th_add(c, th);

    // resume execution
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        kill(pid, SIGKILL);
        th_rm(&(c->threads));
        free(th);
        return false;
    }

    return true;
}


void handle_syscalls(struct c_t * * start_c_p) {
    int untraced_count = 0;  // number of threads spawned, but untraced yet

    // container of threads not assigned to any container (because we didn't get PTRACE_EVENT_CLONE from their parent yet)
    struct c_t unassigned_c;
    container_init(&unassigned_c);

    while (*start_c_p != NULL || untraced_count != 0) {
        siginfo_t siginfo;

        /* wait for next system call or exit from syscall */
        if (waitid(P_ALL, 0, &siginfo, WSTOPPED) == -1)
            err(EXIT_FAILURE, "wait for child syscall failed");

        // get relevant thread
        pid_t pid = siginfo.si_pid;
        struct c_t * * c_p = start_c_p;
        struct th_t * * th_p = th_and_c_get_by_tid(&c_p, pid);

        if (th_p == NULL) {
            // we dont know this thread - it's a new thread coming from clone()
            untraced_count --;

            // add to thread list
            struct th_t * new_th = malloc(sizeof(struct th_t));
            if (new_th == NULL) err(EXIT_FAILURE, "malloc failed");
            th_init(new_th);
            th_add(&unassigned_c, new_th);
            new_th->tid = pid;
            new_th->in_syscall = true;

            if (DEBUG) fprintf(stderr, "%d is a new thread, untraced %d\n", pid, untraced_count);

            // dont wake this thread up - first we need to catch parent exiting from clone() to know container scope
            continue;

        } else if (siginfo.si_status == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            // new thread observed from previous old thread
            untraced_count ++;
            if (DEBUG) fprintf(stderr, "%d PTRACE_EVENT_CLONE, untraced %d\n", pid, untraced_count);

        } else if (siginfo.si_status == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
            // thread termination
            struct th_t * th = *th_p;
            th_rm(th_p);
            free(th);
            if ((*c_p)->threads == NULL) container_rm(c_p);
            if (DEBUG) fprintf(stderr, "%d PTRACE_EVENT_EXIT\n", pid);

        } else if (siginfo.si_status == (SIGTRAP | 0x80)) {
            // PTRACE_O_TRACESYSGOOD stop
            struct th_t * th = *th_p;

            /* Gather system call arguments */
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                err(EXIT_FAILURE, "failed to get child registers");

            if (th->in_syscall) {
                // syscall exit
                th->in_syscall = false;

                if (th->custom_syscall_result) {
                    if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.rax), th->syscall_result) == -1)
                        err(EXIT_FAILURE, "failed to set custom syscall result");
                }

                // this is a return from clone() in parent thread
                if (regs.orig_rax == SYS_clone && (long long)regs.rax > 0) {
                    pid_t new_pid = regs.rax;
                    struct c_t * container = th->container;
                    th_p = th_get_by_tid(&(unassigned_c.threads), new_pid);
                    if (*th_p == NULL) {
                        untraced_count --;
                        th = malloc(sizeof(struct th_t));
                        if (th == NULL) err(EXIT_FAILURE, "malloc failed");
                        th_init(th);
                        th->tid = new_pid;
                        th->in_syscall = true;
                        th_add(container, th);
                    } else {
                        th = *th_p;
                        th_rm(th_p);
                        th_add(container, th);
                        th->in_syscall = false;
                        // resume execution
                        if (ptrace(PTRACE_SYSCALL, new_pid, 0, 0) == -1)
                            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
                    }
                }
            } else {
                // syscall enter
                th->in_syscall = true;
                long syscall = regs.orig_rax;

                bool pass_syscall = false;
                int64_t word;
                switch (syscall) {
                    case SYS_mmap:
                        // pass only when fd is -1 (we want to prevent real file maps)
                        pass_syscall = ((long)regs.r8 == -1);
                        th->custom_syscall_result = false;
                        break;

                    case SYS_clone:
                        // check if flags are correct
                        word = regs.rdi;
                        pass_syscall = (
                            (word & CLONE_FILES) &&
                            !(word & CLONE_VFORK) &&
                            (word & CLONE_VM)
                        );
                        th->custom_syscall_result = false;
                        break;

                    case SYS_cnew:
                        do_cnew(th_p, regs.rdi);
                        pass_syscall = false;
                        th->custom_syscall_result = true;
                        th->syscall_result = -42;
                        break;

                    case SYS_write:
                    case SYS_read:

                    case SYS_mprotect:
                    case SYS_munmap:
                    case SYS_mremap:

                    case SYS_exit:
                    case SYS_gettid:
                    case SYS_set_tid_address:
                    case SYS_arch_prctl:
                    case SYS_futex:
                        pass_syscall = true;
                        th->custom_syscall_result = false;
                        break;

                    default:
                        pass_syscall = false;
                        th->custom_syscall_result = false;
                        break;
                }

                if (pass_syscall) {
                    if (DEBUG) fprintf(stderr, "%d pass %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                        pid,
                        syscall,
                        (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                        (long)regs.r10, (long)regs.r8,  (long)regs.r9);
                } else {
                    if (DEBUG) fprintf(stderr, "%d droping syscall %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                        pid,
                        syscall,
                        (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                        (long)regs.r10, (long)regs.r8,  (long)regs.r9);
                    // set to invalid syscall
                    if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.orig_rax), -1) != 0)
                        err(EXIT_FAILURE, "failed to stop syscall from happening (set %%RAX to -1)");
                }
            }

        } else if (siginfo.si_status == SIGSTOP) {
            /* stopped process - possibly new thread coming out from clone() */
            struct th_t * th = *th_p;
            th->in_syscall = false;
        } else if (
            siginfo.si_status == SIGKILL ||
            siginfo.si_status == SIGSEGV
        ) { 
            // killed child
            struct th_t * th = *th_p;
            th_rm(th_p);
            free(th);
            if ((*c_p)->threads == NULL) container_rm(c_p);

            unsigned long long rip = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, regs.rip), 0, 0);
            fprintf(stderr, "%d killed at %p\n", pid, (void *)rip);

        } else {
            struct th_t * th = *th_p;
            errx(
                EXIT_FAILURE,
                "got unknown ptrace event (%d, %d) from thread %d",
                siginfo.si_status >> 8,
                siginfo.si_status & 0xff,
                th->tid
            );
        }

        // resume execution
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
    }

    if (*start_c_p != NULL) warnx("exiting with notempty container list");
    if (untraced_count != 0) warnx("exiting with nonzero untraced threads count");
}

int main () {
    struct c_t c;
    container_init(&c);
    if (!do_cnew(&(c), STDIN_FILENO))
        errx(EXIT_FAILURE, "failed to spawn initial container");
    struct c_t * c_p = &c;
    handle_syscalls(&c_p);
    return EXIT_SUCCESS;
}
