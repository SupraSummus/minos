#ifndef THREAD_H
#define THREAD_H

#include <stdbool.h>
#include <sys/types.h>
#include <uthash.h>

struct c_t {
	int thread_count;
	struct th_t * threads;
	struct c_t * next;
	struct fd_t * rfds;
	struct fd_t * wfds;
};


struct fd_t {
	int inner;  // fd number observed from inside a container
	int fd;

	/* makes this structure hashable */
	UT_hash_handle hh;
};


struct th_t {
	pid_t tid;

	bool in_syscall;
	bool custom_syscall_result;
	long syscall_result;

	// container thread list
	struct c_t * container;
	struct th_t * next;
};


extern void th_init(struct th_t *);
extern void th_add(struct c_t *, struct th_t *);
extern void th_rm(struct th_t * *);
extern struct th_t * * th_and_c_get_by_tid(struct c_t * * *, pid_t pid);
extern struct th_t * * th_get_by_tid(struct th_t * *, pid_t pid);
extern void container_init(struct c_t *);
extern void container_rm(struct c_t * *);
extern void container_add(struct c_t * *, struct c_t *);

#endif
