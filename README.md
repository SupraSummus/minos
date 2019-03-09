MinOS
=====

Proof of concept of minimalistic, heterogenous, virtualization-friendly OS API.

Minos specifies simple API for spawning controlably interconnected computational continers. Each container can operate under its specific architecture. For example several can be executed as x86-64 code, and others as JVM bytecode. Minos architecture doesn't put hard limits on range of possible environments. Only requirements are:

 * code and application state must be serializable into octet stream (bytes)
 * environment must somehow expose minos API to running application - for example it is `syscall` asm instruction on x86-64 platform
 * execution environment must sandbox code running inside, allowing for execution of untrusted programs (in terms of privilege escalation; protection against DoS attacks are not yet proposed)

Communications between containers is asynchronous, via reliable, ordered byte streams, like TCP or UNIX pipe, but minos abstracts that by use of file descriptors. Descriptors are of two types: write-only or read-only. Descriptors can be passed between containers, but single descriptor can be used in at most one container at a time.

General, architecture independant syscalls
------------------------------------------

 * cnew(code_rfd, arch_spec...) -> cid

   Create new virtual memory space. Memory is filled with data written to wfd (begining at architecture-specific addr) and then executed.

 * ckill(cid)

 * pipe() -> (wfd, rfd)
 * write(wfd, addr, size) -> count

   Write at most `size` bytes from `addr` to `wfd`. Return count writen.

 * read(rfds, rfdcount, addr, size) -> (rfd, size)

   Read up to `size` bytes into `addr` from one of read-fds specified in table (`rfds` and `rfdcount`). Return count of bytes read and read-fd read from. Number of bytes read is 0 only if selected rfd is forever empty.

 * wclose(wfd)
 * rclose(rfd)

 * wpass(wfd, vmid) -> child_wfd
 * rpass(rfd, vmid) -> child_rfd

   Pass descriptor to child space. Descripor there will be visible under new id. Descriptor becomes unaccesible in calling container.

Architecture specific container state
-------------------------------------

 * arch_prctl - for example for setting FS, GS register

Paged memory management
-----------------------

 * linux-like mmap/mremap/munmap/mprotect

   mmap is for anonymous-only pages

Threads
-------

 * clone/exit/gettid/...
 * linux-like futex
