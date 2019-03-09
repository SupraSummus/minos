#define _GNU_SOURCE
#include <unistd.h>
#include <minos.h>

int cnew (
	int code_fd,
	int * rfds, unsigned int rfd_count,
	int * wfds, unsigned int wfd_count,
	int arch_spec
) {
	return syscall(SYS_cnew, code_fd, rfds, rfd_count, wfds, wfd_count, arch_spec);
}
