#include <unistd.h>
#include <stdlib.h>
#include <minos.h>
#include <errno.h>
#include <stdio.h>

int main () {
	int code_fd = 0;
	int output_fd = 1;
	write(output_fd, "parent\n", 7);

	int cid = cnew(
		code_fd,
		NULL, 0,
		&output_fd, 1,
		CNEW_X86_64_LINUX_LIKE
	);
	if (cid == -1) {
		printf(/*output_fd,*/ "fail %d\n", errno);
		return EXIT_FAILURE;
	}

	//printf(/*output_fd,*/ "after\n");  // this will fail as we dont own the fd anymore
	return EXIT_SUCCESS;
}
