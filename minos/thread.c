#include "thread.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

void th_init (struct th_t * th) {
    memset(th, 0, sizeof(struct th_t));
}


void th_add (struct c_t * c, struct th_t * th) {
	c->thread_count ++;
	assert(th->next == NULL);
	th->next = c->threads;
	th->container = c;
	c->threads = th;
}

void th_rm (struct th_t * * th_p) {
    struct th_t * th = *th_p;
    *th_p = th->next;
    th->container->thread_count --;
    th->container = NULL;
}

struct th_t * * th_and_c_get_by_tid (struct c_t * * * c_p_p, pid_t pid) {
	while (**c_p_p != NULL) {
		struct th_t * * th_p = th_get_by_tid(&((**c_p_p)->threads), pid);

		// found
		if (*th_p != NULL) return th_p;

		// next container
		*c_p_p = &((**c_p_p)->next);
	}
	return NULL;
}

struct th_t * * th_get_by_tid (struct th_t * * th_p, pid_t pid) {
	while (*th_p != NULL && (*th_p)->tid != pid)
		th_p = &((*th_p)->next);
	return th_p;
}

void container_init (struct c_t * c) {
	memset(c, 0, sizeof(struct c_t));
}

void container_rm(struct c_t * * c_p) {
	struct c_t * c = *c_p;
	*c_p = c->next;
	c->next = NULL;
}
