#include "thread.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

void th_init (struct th_t * th) {
    memset(th, 0, sizeof(struct th_t));
}

void container_init (struct c_t * c) {
	memset(c, 0, sizeof(struct c_t));
}

int get_external_fd(struct fd_t * fds, int internal) {
	struct fd_t * fd;
	HASH_FIND_INT(fds, &internal, fd);
	if (fd == NULL) return -1;
	return fd->fd;
}
