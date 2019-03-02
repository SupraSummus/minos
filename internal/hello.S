.global _start
.section .init

_start:
	// write hello
	movq $1, %rax  // sys_write
	movq $1, %rdi  // stdout
	movq $hello_str, %rsi  // buf ptr
	movq $12, %rdx  // len
	syscall

	// exit(0)
	movq $60, %rax               // system call 60 is exit
	movq $0, %rdi              // we want return code 0
	syscall 

hello_str:
	.asciz "hello world\n"
