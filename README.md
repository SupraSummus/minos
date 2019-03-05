MinOS
-----

Proof of concept of minimalistic, heterogenous, virtualization-friendly OS API.

 * vmnew(arch_spec...) -> vmid, wfd
 
   Create new virtual memory space. Memory is filled with data written to rfd (begining at architecture-specific addr).
 
 * vmforget(vmid)

 * fifonew() -> (wfd, rfd)
 * write(wfd, addr, size) -> success

   Atomicaly write exactly `size` bytes from `addr` to `wfd`. Return if this was sucessful (or possibly error code).

 * read(rfds, rfdcount, addr, size) -> (rfd, size)

   Read up to `size` bytes into `addr` from one of read-fds specified in table (`rfds` and `rfdcount`). Return count of bytes read and read-fd read from. Number of bytes read is 0 only if all rfds are forever empty.

 * wforget(wfd)
 * rforget(rfd)

   Mark file descriptors as unused in current space in the future.

 * wpass(wfd, vmid) -> child_wfd
 * rpass(rfd, vmid) -> child_rfd

   Pass descriptor to child space. Descripor there will be visible under new id.

 * thnew(vmid) -> thid

   Create new thread in given virtual memory space. Start execution at addr specific for vm's architecture. Return created thread's id.

 * thend(vmid, thid)

   Immediately terminate given thread.

 * gettid() -> thid
