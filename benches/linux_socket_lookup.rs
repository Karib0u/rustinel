//! Burst benchmark for Linux network-event socket attribution.
//!
//! ```sh
//! cargo bench --bench linux_socket_lookup
//! ```
//!
//! Resolving one connect's local address means reading the socket inode from
//! `/proc/<pid>/fd/<fd>` and finding it in the system-wide
//! `/proc/net/{tcp,tcp6,udp,udp6}` tables. The tables are unindexed, so the
//! second half of that costs a pass over every socket on the host.
//!
//! The two benchmarks are the two ways of paying it for a burst of events that
//! arrive together, as a drain of the network ring buffer does:
//!
//! * `per_event_scan` gives each event its own inventory, which is the cost
//!   model of scanning the tables once per event.
//! * `batch_inventory` scans once for the whole burst and answers every event
//!   from that snapshot, which is what the sensor does per drain batch.
//!
//! Both read every table, so neither benefits from the family and transport
//! narrowing the sensor applies, and the gap between them is scan work
//! removed, and it widens with both the burst size and the number of sockets
//! on the host. The harness prints the scan counts each arm paid so the ratio
//! is readable without inferring it from the timings.
//!
//! Linux only: there is no `/proc/net` to scan anywhere else.

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();

    #[cfg(not(target_os = "linux"))]
    eprintln!("linux_socket_lookup: skipped, /proc/net exists only on Linux");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::hint::black_box;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use criterion::{BenchmarkId, Criterion};
    use rustinel::utils::{SocketInventory, SocketTableSet};

    /// Connected sockets to attribute in one burst. Chosen to be larger than a
    /// quiet drain and smaller than a pathological one, so the amortisation is
    /// visible without the setup dominating the run.
    const BURST: usize = 256;

    /// Sockets held open by the benchmark itself, on top of whatever the host
    /// already has. They are what makes a table scan cost something, so the
    /// arms are compared against a table that is not almost empty.
    struct Burst {
        _listener: TcpListener,
        _accepted: Vec<TcpStream>,
        clients: Vec<TcpStream>,
    }

    fn burst() -> Burst {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");

        let mut clients = Vec::with_capacity(BURST);
        let mut accepted = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            clients.push(TcpStream::connect(addr).expect("connect"));
            accepted.push(listener.accept().expect("accept").0);
        }

        Burst {
            _listener: listener,
            _accepted: accepted,
            clients,
        }
    }

    /// A policy that never refuses a refresh, so the batch arm is measured on
    /// the amortisation itself rather than on a wall-clock floor that would
    /// make the result depend on how fast the machine ran the loop.
    fn inventory() -> SocketInventory {
        SocketInventory::with_refresh_policy(Duration::ZERO, Duration::from_secs(3600), 0)
    }

    pub fn main() {
        let mut criterion = Criterion::default().configure_from_args();
        let burst = burst();
        let pid = std::process::id();
        let fds: Vec<i32> = burst
            .clients
            .iter()
            .map(|client| client.as_raw_fd())
            .collect();

        report_scan_counts(pid, &fds);

        let mut group = criterion.benchmark_group("linux_socket_lookup");
        group.throughput(criterion::Throughput::Elements(fds.len() as u64));

        group.bench_function(BenchmarkId::new("per_event_scan", fds.len()), |b| {
            b.iter(|| {
                for fd in &fds {
                    let mut sockets = inventory();
                    sockets.refresh_if_due(SocketTableSet::EVERY);
                    black_box(sockets.lookup(pid, *fd));
                }
            });
        });

        group.bench_function(BenchmarkId::new("batch_inventory", fds.len()), |b| {
            b.iter(|| {
                let mut sockets = inventory();
                sockets.refresh_if_due(SocketTableSet::EVERY);
                for fd in &fds {
                    black_box(sockets.lookup(pid, *fd));
                }
            });
        });

        group.finish();
        criterion.final_summary();
    }

    /// Print the table scans each arm pays for one burst, and assert both
    /// resolve every socket: an arm that answers fewer of them is faster for
    /// the wrong reason and its timing means nothing.
    fn report_scan_counts(pid: u32, fds: &[i32]) {
        let mut per_event_scans = 0;
        let mut per_event_resolved = 0;
        for fd in fds {
            let mut sockets = inventory();
            sockets.refresh_if_due(SocketTableSet::EVERY);
            per_event_resolved += usize::from(sockets.lookup(pid, *fd).is_some());
            per_event_scans += sockets.scans();
        }

        let mut batched = inventory();
        batched.refresh_if_due(SocketTableSet::EVERY);
        let mut batch_resolved = 0;
        for fd in fds {
            batch_resolved += usize::from(batched.lookup(pid, *fd).is_some());
        }

        assert_eq!(
            per_event_resolved,
            fds.len(),
            "per-event arm failed to resolve every socket"
        );
        assert_eq!(
            batch_resolved,
            fds.len(),
            "batch arm failed to resolve every socket"
        );

        println!(
            "linux_socket_lookup: {} sockets in the snapshot; {} events cost {} table scans per-event vs {} batched",
            batched.len(),
            fds.len(),
            per_event_scans,
            batched.scans(),
        );
    }
}
