.global __setup_stack_and_start
.section .init

#define PAGE_SIZE 0x1000

__setup_stack_and_start:
	// mmap stack area
	mov $9, %rax  // sys_mmap
	mov $0, %rdi  // NULL addr - let OS choose something
	mov $PAGE_SIZE, %rsi
	mov $0x3, %rdx  // PROT_READ | PROT_WRITE
	mov $0x122, %r10  // MAP_GROWSDOWN | MAP_ANONYMOUS | MAP_PRIVATE
	mov $-1, %r8  // fd
	mov $0, %r9 // fd offset
	syscall

	// stack base is at the end of mapped page
	add $PAGE_SIZE, %rax
	mov %rax, %rsp

	// initialize argv, envp, ...
	pushq $0
	pushq $0
	pushq $0
	pushq $0
	pushq $0

	jmp _start

