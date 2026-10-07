fn main() {
    // Only build/embed eBPF programs when compiling for Linux.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "linux" {
        build_ebpf();
    }
}

// Not every item is used on every host OS the build script runs on.
#[allow(dead_code)]
#[path = "build/ebpf_select.rs"]
mod ebpf_select;

use ebpf_select::{Inputs, ObjectSource};

/// Newest modification time under the paths the eBPF object is built from.
fn newest_modified(paths: &[std::path::PathBuf]) -> Option<std::time::SystemTime> {
    fn walk(path: &std::path::Path, newest: &mut Option<std::time::SystemTime>) {
        let Ok(metadata) = std::fs::metadata(path) else {
            return;
        };
        if metadata.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    walk(&entry.path(), newest);
                }
            }
        } else if let Ok(modified) = metadata.modified() {
            if newest.is_none_or(|current| modified > current) {
                *newest = Some(modified);
            }
        }
    }
    let mut newest = None;
    for path in paths {
        walk(path, &mut newest);
    }
    newest
}

fn build_ebpf() {
    use std::{env, path::PathBuf, process::Command};

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let dst = out_dir.join("rustinel-ebpf");

    // Re-run when anything the object is built from changes, or when the way it
    // is chosen changes.
    println!("cargo:rerun-if-changed=ebpf/src");
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/Cargo.lock");
    println!("cargo:rerun-if-changed=ebpf-common/src");
    println!("cargo:rerun-if-changed=ebpf-common/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/rustinel-ebpf.o");
    println!("cargo:rerun-if-changed=build/ebpf_select.rs");
    println!("cargo:rerun-if-env-changed=RUSTINEL_EBPF_STUB");
    println!("cargo:rerun-if-env-changed=RUSTINEL_EBPF_PREBUILT");

    let pre_built = manifest_dir.join("ebpf/rustinel-ebpf.o");
    let flag = |name: &str| env::var(name).as_deref() == Ok("1");
    let selection = ebpf_select::select(Inputs {
        stub_requested: flag("RUSTINEL_EBPF_STUB"),
        prebuilt_forced: flag("RUSTINEL_EBPF_PREBUILT"),
        prebuilt_modified: std::fs::metadata(&pre_built)
            .and_then(|metadata| metadata.modified())
            .ok(),
        newest_input_modified: newest_modified(&[
            manifest_dir.join("ebpf/src"),
            manifest_dir.join("ebpf/Cargo.toml"),
            manifest_dir.join("ebpf/Cargo.lock"),
            manifest_dir.join("ebpf-common/src"),
            manifest_dir.join("ebpf-common/Cargo.toml"),
        ]),
    })
    .unwrap_or_else(|message| panic!("{message}"));
    if let Some(warning) = &selection.warning {
        println!("cargo:warning={warning}");
    }
    // The sensor reports this at startup and refuses to run with a stub.
    println!(
        "cargo:rustc-env=RUSTINEL_EBPF_SOURCE={}",
        selection.source.as_str()
    );

    match selection.source {
        ObjectSource::Prebuilt => {
            std::fs::copy(&pre_built, &dst)
                .unwrap_or_else(|e| panic!("failed to copy pre-built eBPF artifact: {e}"));
            return;
        }
        ObjectSource::Stub => {
            // Skips the nightly/bpf-linker build and writes a bare ELF64 LE/BPF
            // header. Use this for cargo check / clippy / unit tests where the
            // nightly toolchain is unavailable.
            write_ebpf_stub(&dst);
            return;
        }
        ObjectSource::Source => {}
    }

    // Compile from source using the nightly toolchain.
    let ebpf_dir = manifest_dir.join("ebpf");
    let status = Command::new("cargo")
        .args(["+nightly", "build", "--release", "--bin", "rustinel-ebpf"])
        .current_dir(&ebpf_dir)
        // The parent stable-cargo process exports CARGO pointing to the
        // stable rustc. If that propagates into the nightly sub-build,
        // Cargo uses the stable compiler for eBPF dependencies
        // (bpfel-unknown-none), which fails. Drop it so the nightly toolchain
        // sets its own CARGO path.
        .env_remove("CARGO")
        // Cargo also sets RUSTC to the stable rustc binary. Nightly cargo
        // honours RUSTC when locating the compiler and sysroot (for
        // build-std), so leaving it set causes `rustc --print sysroot` to
        // return the stable sysroot — which has no rust-src.
        .env_remove("RUSTC")
        // Cargo sets RUSTUP_TOOLCHAIN to the active stable toolchain when
        // running build scripts. That overrides the +nightly argument above,
        // causing cargo to look for rust-src in the stable sysroot (which
        // doesn't have it) instead of the nightly one.
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()
        .expect(
            "failed to invoke cargo for eBPF build — \
             install the nightly toolchain or run scripts/build-ebpf.sh first",
        );

    assert!(
        status.success(),
        "eBPF program build failed — see output above"
    );

    let src = ebpf_dir.join("target/bpfel-unknown-none/release/rustinel-ebpf");
    std::fs::copy(&src, &dst)
        .unwrap_or_else(|e| panic!("failed to copy compiled eBPF artifact from {src:?}: {e}"));
}

/// Write a minimal valid ELF64 LE/BPF header to `dst`.
///
/// The resulting file satisfies `aya::include_bytes_aligned!` at compile time
/// but contains no programs — it must never be loaded by a live kernel.
/// Only used when `RUSTINEL_EBPF_STUB=1`.
fn write_ebpf_stub(dst: &std::path::Path) {
    use std::io::Write;

    // ELF64 little-endian, eBPF machine (0xf7), no sections or segments.
    #[rustfmt::skip]
    let header: [u8; 64] = [
        // e_ident: magic, class=64-bit, data=LE, version=1, OS/ABI=0, padding
        0x7f, b'E', b'L', b'F', 2, 1, 1, 0,  0, 0, 0, 0, 0, 0, 0, 0,
        // e_type=ET_EXEC(2), e_machine=EM_BPF(0xf7), e_version=1
        2, 0,  0xf7, 0,  1, 0, 0, 0,
        // e_entry, e_phoff, e_shoff (all zero)
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        // e_flags=0, e_ehsize=64, e_phentsize=56, e_phnum=0
        0, 0, 0, 0,  64, 0,  56, 0,  0, 0,
        // e_shentsize=64, e_shnum=0, e_shstrndx=0
        64, 0,  0, 0,  0, 0,
    ];

    let mut f = std::fs::File::create(dst)
        .unwrap_or_else(|e| panic!("failed to create eBPF stub at {dst:?}: {e}"));
    f.write_all(&header)
        .unwrap_or_else(|e| panic!("failed to write eBPF stub: {e}"));
}
