#ifndef THREAD_H
#define THREAD_H

#include <stdbool.h>
#include <sys/types.h>
#include <uthash.h>

struct c_t {
	int thread_count;
	struct th_t * threads;
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
	struct th_t * prev;
	struct th_t * next;

	/* threads are stored in a hashmap (where pid is the key) */
	UT_hash_handle hh;
};


extern void th_init(struct th_t *);
extern void container_init(struct c_t *);

#endif
