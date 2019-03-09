#include "consts.h"

.section .text
.globl purge
.type purge, @function

purge:
	// store first argument
	movq %rdi, %r12

	// unmap before
	movq $11, %rax  // sys_munmap
	movq $0, %rdi  // start
	movq $ENTRY_POINT, %rsi  // len
	syscall

	// unmap after
	movq $11, %rax  // sys_munmap
	movq $(PAGE_SIZE + ENTRY_POINT), %rdi  // start
	movq $(MAX_ADDR - PAGE_SIZE - ENTRY_POINT), %rsi  // len
	syscall

	// unmap vsyscall -- this doesn't seem to work
	movq $11, %rax  // sys_munmap
	movq $0xffffffffff600000, %rdi  // start
	movq $0x1000, %rsi  // len
	syscall

	// grow initial area to desired size (from first arg)
	movq $25, %rax  // sys_mremap
	movq $ENTRY_POINT, %rdi  // old addr
	movq $PAGE_SIZE, %rsi  // old len
	movq %r12, %rdx  // new len
	movq $0, %r10  // flags
	movq $0, %r8  // new addr
	syscall

	// read stdin, just for debug
	//movq $0, %rax  // sys_read
	//movq $0, %rdi  // stdin
	//movq $512, %rsi  // buf ptr
	//movq $1, %rdx  // one byte
	//syscall

	// request ptrace
	movq $101, %rax  // sys_ptrace
	movq $0, %rdi  // PTRACE_TRACEME
	movq $0, %rsi
	movq $0, %rdx
	movq $0, %r10
	syscall

	.zero PAGE_SIZE  // padding for easy coping
