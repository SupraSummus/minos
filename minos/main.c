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
#include <errno.h>
#include <utlist.h>


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


bool set_ptrace_options (pid_t pid) {
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


bool do_cnew (struct c_t * c, int rfd, struct th_t * * threads) {
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
    pid_t pid = syscall(
        SYS_clone,
        CLONE_FILES | SIGCHLD,
        0, 0, 0
    );
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
    th->container = c;
    DL_APPEND(c->threads, th);
    HASH_ADD_INT(*threads, tid, th);

    // resume execution
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        kill(pid, SIGKILL);
        DL_DELETE(c->threads, th);
        HASH_DEL(*threads, th);
        free(th);
        return false;
    }

    return true;
}


void handle_syscalls(struct th_t * * threads_p) {
    int untraced_count = 0;  // number of threads spawned, but untraced yet

    // collection of threads not assigned to any container (because we didn't catch their parent exiting clone() yet)
    struct th_t * unassigned = NULL;

    while (*threads_p != NULL || untraced_count != 0) {
        siginfo_t siginfo;

        /* wait for next system call or exit from syscall */
        if (waitid(P_ALL, 0, &siginfo, WSTOPPED) == -1)
            err(EXIT_FAILURE, "wait for child syscall failed");

        // get relevant thread
        pid_t pid = siginfo.si_pid;
        struct th_t * thread;
        HASH_FIND_INT(*threads_p, &pid, thread);

        if (thread == NULL) {
            // we dont know this thread - it's a new thread coming from clone()
            untraced_count --;

            // add to thread list
            struct th_t * new_th = malloc(sizeof(struct th_t));
            if (new_th == NULL) err(EXIT_FAILURE, "malloc failed");
            th_init(new_th);
            new_th->tid = pid;
            new_th->in_syscall = true;
            HASH_ADD_INT(unassigned, tid, new_th);

            if (DEBUG) fprintf(stderr, "%d is a new thread, untraced %d\n", pid, untraced_count);

            // dont wake this thread up - first we need to catch parent exiting from clone() to know container scope
            continue;

        } else if (siginfo.si_status == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            // new thread observed from previous old thread
            untraced_count ++;
            if (DEBUG) fprintf(stderr, "%d PTRACE_EVENT_CLONE, untraced %d\n", pid, untraced_count);

        } else if (
            siginfo.si_status == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)) ||
            siginfo.si_status == SIGKILL ||
            siginfo.si_status == SIGSEGV
        ) {
            // thread termination
            DL_DELETE(thread->container->threads, thread);
            HASH_DEL(*threads_p, thread);
            if (thread->container->threads == NULL) {
                free(thread->container);
            }
            free(thread);

            if (DEBUG) fprintf(stderr, "%d exiting, remaining %d threads\n", pid, HASH_COUNT(*threads_p));

        } else if (siginfo.si_status == (SIGTRAP | 0x80)) {
            // PTRACE_O_TRACESYSGOOD stop

            /* Gather system call arguments */
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
                err(EXIT_FAILURE, "failed to get child registers");

            if (thread->in_syscall) {
                // syscall exit
                thread->in_syscall = false;

                if (thread->custom_syscall_result) {
                    if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.rax), thread->syscall_result) == -1)
                        err(EXIT_FAILURE, "failed to set custom syscall result");
                }

                // this is a return from clone() in parent thread
                if (regs.orig_rax == SYS_clone && (long long)regs.rax > 0) {
                    pid_t new_pid = regs.rax;
                    struct th_t * new_thread;
                    HASH_FIND_INT(unassigned, &new_pid, new_thread);
                    if (new_thread == NULL) {
                        untraced_count --;
                        new_thread = malloc(sizeof(struct th_t));
                        if (new_thread == NULL) err(EXIT_FAILURE, "malloc failed");
                        th_init(new_thread);
                        new_thread->tid = new_pid;
                        new_thread->in_syscall = true;
                        new_thread->container = thread->container;
                        DL_APPEND(thread->container->threads, new_thread);
                        HASH_ADD_INT(*threads_p, tid, new_thread);
                    } else {
                        HASH_DEL(unassigned, new_thread);
                        HASH_ADD_INT(*threads_p, tid, new_thread);
                        DL_APPEND(thread->container->threads, new_thread);
                        new_thread->container = thread->container;
                        new_thread->in_syscall = false;
                        // resume execution of child thread
                        if (ptrace(PTRACE_SYSCALL, new_pid, 0, 0) == -1)
                            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
                    }
                }
            } else {
                // syscall enter
                thread->in_syscall = true;
                long syscall = regs.orig_rax;

                bool pass_syscall = false;
                int64_t word;
                switch (syscall) {
                    case SYS_mmap:
                        // pass only when fd is -1 (we want to prevent real file maps)
                        pass_syscall = ((long)regs.r8 == -1);
                        thread->custom_syscall_result = false;
                        break;

                    case SYS_clone:
                        // check if flags are correct
                        word = regs.rdi;
                        pass_syscall = (
                            (word & CLONE_FILES) &&
                            !(word & CLONE_VFORK) &&
                            (word & CLONE_VM)
                        );
                        thread->custom_syscall_result = false;
                        break;

                    case SYS_cnew:
                        (void)1; // local var declaration cant be first
                        struct c_t * new_c = malloc(sizeof(struct c_t));
                        if (new_c == NULL) err(EXIT_FAILURE, "malloc failed");
                        container_init(new_c);
                        pass_syscall = false;
                        thread->custom_syscall_result = true;

                        int inner_fd = regs.rdi;
                        struct fd_t * fd; 
                        HASH_FIND_INT(thread->container->rfds, &inner_fd, fd);
                        if (fd == NULL) {
                            thread->syscall_result = -EBADF;
                        } else {
                            bool result = do_cnew(new_c, fd->fd, threads_p);
                            if (result) {
                                thread->syscall_result = 0;
                                HASH_DEL(thread->container->rfds, fd);
                                free(fd);
                            } else {
                                thread->syscall_result = -1;
                                free(new_c);
                            }
                        }
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
                        thread->custom_syscall_result = false;
                        break;

                    default:
                        pass_syscall = false;
                        thread->custom_syscall_result = false;
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
            thread->in_syscall = false;

        } else {
            errx(
                EXIT_FAILURE,
                "got unknown ptrace event (%d, %d) from thread %d",
                siginfo.si_status >> 8,
                siginfo.si_status & 0xff,
                thread->tid
            );
        }

        // resume execution
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            err(EXIT_FAILURE, "failed PTRACE_SYSCALL");
    }

    if (*threads_p != NULL) warnx("exiting with notempty thread list");
    if (untraced_count != 0) warnx("exiting with nonzero untraced threads count");
    if (unassigned != NULL) warnx("exiting with nonzero unassigned threads count");
}

bool parse_fds(char * str, struct fd_t * * fds) {
    assert(HASH_COUNT(*fds) == 0);

    char * end;
    int i = 0;
    while (true) {
        // parse fd info
        long fd = strtol(str, &end, 0);
        if (end == str) {
            if (*end == '-') {
                fd = -1;
                end++;
            } else {
                warnx("unexpected character '%c'", *str);
                // TODO free fds stored up to this point
                return false;
            }
        }

        // store in hashmap
        struct fd_t * fd_s = malloc(sizeof(struct fd_t));
        if (fd_s == NULL) err(EXIT_FAILURE, "malloc failed");
        fd_s->inner = i;
        fd_s->fd = fd;
        HASH_ADD_INT(*fds, inner, fd_s);

        // advance to next number
        i++;
        str = end;
        if (*str == ',') {
            str++;
        } else if (*str == '\0') {
            return true;
        }
    }
}

int main (int argc, char * * argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s CODE_RFD RFD0,.. WFD0,..\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char * end;
    int code_fd = strtol(argv[1], &end, 0);
    if (*end != '\0') errx(EXIT_FAILURE, "failed to parse code fd");

    struct c_t * container = malloc(sizeof(struct c_t));
    if (container == NULL) err(EXIT_FAILURE, "malloc failed");
    container_init(container);

    if (!parse_fds(argv[2], &(container->rfds))) {
        errx(EXIT_FAILURE, "failed to parse rfds");
        
    }
    if (!parse_fds(argv[3], &(container->wfds))) {
        errx(EXIT_FAILURE, "failed to parse wfds");
    }

    struct th_t * threads = NULL;

    if (!do_cnew(container, code_fd, &threads))
        errx(EXIT_FAILURE, "failed to spawn initial container");

    handle_syscalls(&threads);
    return EXIT_SUCCESS;
}
