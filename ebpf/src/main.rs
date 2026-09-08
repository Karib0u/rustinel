//! Rustinel eBPF programs — Linux sensor kernel side.
//!
//! This crate is compiled for the `bpfel-unknown-none` target (BPF little-endian,
//! no OS) and produces an ELF object containing all eBPF programs for the
//! Linux MVP sensor:
//!
//! | Program               | Hook                        | Purpose         |
//! |-----------------------|-----------------------------|-----------------|
//! | `handle_exec`         | `sched/sched_process_exec`  | Event 1         |
//! | `handle_exit`         | `sched/sched_process_exit`  | cache cleanup   |
//! | `handle_execve`       | `syscalls/sys_enter_execve` | capture argv    |
//! | `handle_execveat`     | `syscalls/sys_enter_execveat`| capture argv   |
//! | `handle_connect`      | `syscalls/sys_enter_connect`| queue Event 3   |
//! | `handle_connect_exit` | `syscalls/sys_exit_connect` | emit Event 3    |
//! | `handle_socket`       | `syscalls/sys_enter_socket` | capture type    |
//! | `handle_socket_exit`  | `syscalls/sys_exit_socket`  | index fd type   |
//! | `handle_open*`        | `sys_enter_open/openat/openat2` | queue file event |
//! | `handle_creat`        | `syscalls/sys_enter_creat`  | queue Event 11 |
//! | `handle_vfs_create`   | `kprobe/vfs_create`         | confirm create |
//! | `handle_open*_exit`   | `sys_exit_open/openat/openat2` | emit file event |
//! | `handle_unlink*`      | `sys_enter_unlink/unlinkat` | queue Event 23 |
//! | `handle_unlink*_exit` | `sys_exit_unlink/unlinkat`  | emit Event 23 |
//! | `handle_rename*`      | `sys_enter_rename/renameat/renameat2` | queue rename |
//! | `handle_rename*_exit` | `sys_exit_rename/renameat/renameat2` | emit rename |
//! | `handle_mkdir*`       | `sys_enter_mkdir/mkdirat` | queue directory create |
//! | `handle_mkdir*_exit`  | `sys_exit_mkdir/mkdirat` | emit directory create |
//! | `handle_rmdir`        | `syscalls/sys_enter_rmdir`  | queue directory delete |
//! | `handle_rmdir_exit`   | `syscalls/sys_exit_rmdir`   | emit directory delete |
//! | `handle_sendto`       | `syscalls/sys_enter_sendto`  | emit DNS query |
//! | `handle_sendmsg`      | `syscalls/sys_enter_sendmsg` | emit DNS query |
//! | `handle_sendmmsg`     | `syscalls/sys_enter_sendmmsg`| emit DNS query |
//!
//! Requirements: Linux 5.8+ with BTF enabled (CO-RE / ring-buffer support).

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

pub mod dns;
pub mod events;
pub mod file;
pub mod network;
pub mod process;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
