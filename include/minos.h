#ifndef MINOS_H
#define MINOS_H

#define MINOS_SYSCALL_BITS (0x4400)
#define SYS_cnew (MINOS_SYSCALL_BITS | 0x1)

#define CNEW_X86_64_LINUX_LIKE (1)

extern int cnew (
	int code_fd,
	int * rfds, unsigned int rfd_count,
	int * wfds, unsigned int wfd_count,
	int arch_spec
);

#endif
