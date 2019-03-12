#include <unistd.h>
#include <stdlib.h>
#include <minos.h>
#include <errno.h>
#include <stdio.h>

int main () {
	int code_fd = 0;
	int fds[2] = {-1, 1};
	write(1, "parent\n", 7);

	int cid = cnew(
		code_fd,
		fds, 0, 2,
		CNEW_X86_64_LINUX_LIKE
	);
	if (cid == -1) {
		printf("fail %d\n", errno);
		return EXIT_FAILURE;
	}

	write(1, "after\n", 6);  // this will fail as we dont own the fd anymore
	return EXIT_SUCCESS;
}
