// Target binary for YARA memory-scan integration tests.
//
// Allocates RUSTINEL_TEST_MARKER in a touched 32 MiB buffer so it lands in an
// anonymous private mapping on supported targets.
// Prints "READY:{pid}" then loops until killed.
//
// Build:  cargo build --example memory_target
// Run:    target\debug\examples\memory_target.exe   (killed by test or Ctrl+C)
use std::{hint::black_box, io::Write, thread, time::Duration};

fn main() {
    let marker = b"RUSTINEL_TEST_MARKER";
    let mut allocation = vec![0_u8; 32 * 1024 * 1024];
    for page in allocation.chunks_mut(4096) {
        page[0] ^= 1;
    }
    allocation[..marker.len()].copy_from_slice(marker);

    // Announce readiness; flush so the parent process can synchronise.
    println!("READY:{}", std::process::id());
    std::io::stdout().flush().ok();

    loop {
        thread::sleep(Duration::from_secs(1));
        // Prevent the compiler from optimising the live allocation away.
        black_box(&allocation);
    }
}
