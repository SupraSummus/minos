MinOS
-----

Proof of concept of minimalistic, virtualization-friendly OS API.

 * vmnew(arch_spec...) -> vmid
 * vmforget(vmid_path, path_size)
 * vmls(vmid_path, path_size) -> ...

 * fifonew() -> (wfd, rfd)
 * write(wfd, vmid_path, path_size, addr, size) -> success

   Atomicaly write exactly `size` bytes from `addr` to `wfd`, where `addr` is in given virtual memory space (`vmid_path`, `path_size`). Return if this was sucessful (or possibly error code).

 * read(rfds, rfdcount, vmid_path, path_size, addr, size) -> (rfd, size)

   Read up to `size` bytes into `addr` (under given virtual memory) from one of read-fds specified in table (`rfds` and `rfdcount`). Return count of bytes read and read-fd read from. Number of bytes read is 0 only if all rfds are forever empty.

 * wforget(wfd)
 * rforget(rfd)

   Mark file descriptors as unused in current space in the future.

 * wdelegate(wfd, vmid_path, path_size) -> child_wfd
 * rdelegate(rfd, wmid_path, path_size) -> child_rfd

   Pass descriptor to child space. Descripor there will be visible under new id.

 * thnew(vmid_path, path_size, addr) -> thid

   Create new thread in given virtual memory space. Start execution at `addr`. Return created thread's id.

 * thend(vmid_path, path_size, thid)

   Immediately terminate given thread.

 * gettid() -> thid
 * thls(vmid_path, path_size) -> ...
