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
