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
//! | `handle_connect`      | `syscalls/sys_enter_connect`| Event 3         |
//! | `handle_openat`       | `syscalls/sys_enter_openat` | queue Event 11  |
//! | `handle_vfs_create`   | `kprobe/vfs_create`         | confirm create  |
//! | `handle_openat_exit`  | `syscalls/sys_exit_openat`  | emit Event 11   |
//! | `handle_unlinkat`     | `syscalls/sys_enter_unlinkat`| queue Event 23 |
//! | `handle_unlinkat_exit`| `syscalls/sys_exit_unlinkat`| emit Event 23  |
//! | `handle_renameat`     | `syscalls/sys_enter_renameat` | queue rename |
//! | `handle_renameat_exit`| `syscalls/sys_exit_renameat`  | emit rename  |
//! | `handle_renameat2`    | `syscalls/sys_enter_renameat2`| queue rename |
//! | `handle_renameat2_exit`| `syscalls/sys_exit_renameat2`| emit rename |
//! | `handle_sendto`       | `syscalls/sys_enter_sendto`  | emit DNS query |
//! | `handle_sendmsg`      | `syscalls/sys_enter_sendmsg` | emit DNS query |
//! | `handle_sendmmsg`     | `syscalls/sys_enter_sendmmsg`| emit DNS query |
//!
//! Requirements: Linux 5.8+ with BTF enabled (CO-RE / ring-buffer support).

#![no_std]
#![no_main]

pub mod dns;
pub mod events;
pub mod file;
pub mod network;
pub mod process;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
