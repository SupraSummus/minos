#define _GNU_SOURCE
#include <unistd.h>
#include <minos.h>

int cnew (
	int code_fd,
	int * fds,
	unsigned int rfd_count,
	unsigned int wfd_count,
	int arch_spec
) {
	return syscall(SYS_cnew, code_fd, fds, rfd_count, wfd_count, arch_spec);
}
