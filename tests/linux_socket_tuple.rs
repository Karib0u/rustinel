#![cfg(target_os = "linux")]

use rustinel::sensor::{linux::EbpfSensor, RawPayload, Sensor, SensorAction};
use rustinel_ebpf_common::socket_tuple_abi::{UDP_BUDGET_NS, UDP_DEDUP_NS, UDP_EVENTS_PER_WINDOW};
use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

#[test]
fn running_kernel_socket_layout() {
    if std::fs::File::open("/sys/kernel/btf/vmlinux").is_err() {
        eprintln!("RUSTINEL_TEST_SKIPPED: /sys/kernel/btf/vmlinux is not readable");
        assert!(
            std::env::var_os("RUSTINEL_FAIL_ON_SKIP").is_none(),
            "kernel BTF is required (RUSTINEL_FAIL_ON_SKIP is set)"
        );
        return;
    }
    let layout = rustinel::sensor::linux::task_btf::SocketLayout::load().unwrap();
    println!(
        "sk_protocol offset={}, width={}, accept={}",
        layout.offsets.protocol, layout.offsets.protocol_width, layout.accept_program
    );
}

/// Use a local interface address so both connect and accept can be checked
/// without an external server. The UDP route lookup sends no packets.
fn local_ip() -> std::net::IpAddr {
    let route = UdpSocket::bind("0.0.0.0:0").unwrap();
    route.connect("192.0.2.1:9").unwrap();
    route.local_addr().unwrap().ip()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires eBPF privileges, tracefs, BTF, and a built object"]
async fn live_tuple_and_connection_churn() {
    let ip = local_ip();
    let listener = TcpListener::bind((ip, 0)).unwrap();
    let server = listener.local_addr().unwrap();
    // A socket created before attachment must still report measured UDP.
    let udp = UdpSocket::bind((ip, 0)).unwrap();
    let udp_source = udp.local_addr().unwrap();
    let sensor = EbpfSensor::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(32768);
    sensor.start(tx).unwrap();
    let snapshot = sensor.telemetry().unwrap();
    assert!(
        snapshot
            .features
            .iter()
            .any(|f| f.feature == "network_tuple" && f.active),
        "{snapshot:?}"
    );

    udp.connect(server).unwrap();
    let udp_port = udp_source.port().to_string();
    let server_port = server.port().to_string();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    // The sensor reports the kernel TGID, which can differ from getpid in a PID namespace.
    let pid = loop {
        let event = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("UDP connect was not captured")
            .unwrap();
        let RawPayload::Network(fields) = event.payload else {
            continue;
        };
        if fields.protocol.as_deref() == Some("udp")
            && fields.source_port.as_deref() == Some(udp_port.as_str())
            && fields.destination_port.as_deref() == Some(server_port.as_str())
        {
            assert_eq!(fields.source_ip.as_deref(), Some(ip.to_string().as_str()));
            assert_eq!(
                fields.destination_ip.as_deref(),
                Some(ip.to_string().as_str())
            );
            assert_eq!(fields.initiated, Some(true));
            break event.pid.expect("UDP connect carries a process ID");
        }
    };
    let count = 2000;
    let start = Instant::now();
    let churn = tokio::task::spawn_blocking(move || {
        let accepter = std::thread::spawn(move || {
            for _ in 0..count {
                drop(listener.accept().unwrap());
            }
        });
        for _ in 0..count {
            drop(TcpStream::connect(server).unwrap());
        }
        accepter.join().unwrap();
    });
    let mut outbound = 0;
    let mut inbound = 0;
    let mut max_delay = Duration::ZERO;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while outbound + inbound < count * 2 {
        let event = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("drain stalled or lost connection events")
            .unwrap();
        if event.pid != Some(pid) || event.action != SensorAction::Connect {
            continue;
        }
        let RawPayload::Network(fields) = event.payload else {
            continue;
        };
        max_delay = max_delay.max(event.timestamp.elapsed().unwrap_or_default());
        assert_eq!(fields.source_ip.as_deref(), Some(ip.to_string().as_str()));
        assert_eq!(
            fields.destination_ip.as_deref(),
            Some(ip.to_string().as_str())
        );
        assert_eq!(fields.protocol.as_deref(), Some("tcp"));
        assert!(fields.source_port.is_some());
        assert_eq!(
            fields.destination_port.as_deref(),
            Some(server.port().to_string().as_str())
        );
        if fields.initiated == Some(true) {
            outbound += 1;
        } else {
            inbound += 1;
        }
    }
    churn.await.unwrap();
    println!("{count} TCP connections: outbound={outbound}, inbound={inbound}, elapsed={:?}, max_drain_delay={max_delay:?}", start.elapsed());
    assert!(
        max_delay < Duration::from_secs(2),
        "ring drain stalled: {max_delay:?}"
    );

    // Both IPv4 and IPv6 loopback must disappear before the ring buffer.
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = TcpListener::bind(address).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        drop(listener.accept().unwrap());
        drop(stream);
    }
    let until = tokio::time::Instant::now() + Duration::from_millis(250);
    while let Ok(Some(event)) = tokio::time::timeout_at(until, rx.recv()).await {
        if event.pid == Some(pid) && event.action == SensorAction::Connect {
            assert!(
                !matches!(event.payload, RawPayload::Network(_)),
                "loopback leaked to ring"
            );
        }
    }
    sensor.shutdown();
}

fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: now is a writable timespec.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    assert_eq!(result, 0);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

fn sendmsg_udp(socket: &UdpSocket, destination: SocketAddrV4) {
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: destination.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    // SAFETY: zero initializes the optional fields of msghdr.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::from_ref(&address).cast_mut().cast();
    msg.msg_namelen = std::mem::size_of_val(&address) as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: msg and its buffers remain valid throughout the syscall.
    assert_eq!(unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) }, 1);
}

fn open_socket(family: i32, ty: i32, protocol: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: socket takes integers and returns an owned descriptor on success.
    let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is live and its ownership has not been transferred.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires eBPF privileges, tracefs, BTF, CAP_NET_RAW, and a built object"]
async fn live_listen_udp_and_raw_sockets() {
    let sensor = EbpfSensor::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    sensor.start(tx).unwrap();
    let snapshot = sensor.telemetry().unwrap();
    for feature in ["network_listen", "network_udp_send", "network_raw_socket"] {
        assert!(
            snapshot
                .features
                .iter()
                .any(|f| { f.feature == feature && f.active && f.unavailable_hooks.is_empty() }),
            "{feature}: {snapshot:?}"
        );
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_port = listener.local_addr().unwrap().port().to_string();
    let duplicate = listener.try_clone().unwrap();
    // SAFETY: the duplicate socket descriptor is valid.
    assert_eq!(unsafe { libc::listen(duplicate.as_raw_fd(), 64) }, 0);

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let std::net::SocketAddr::V4(destination) = peer.local_addr().unwrap() else {
        unreachable!();
    };
    let udp_port = destination.port().to_string();
    let udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let peer6 = UdpSocket::bind("[::1]:0").unwrap();
    let udp6_port = peer6.local_addr().unwrap().port().to_string();

    // Keep repeated sends within one dedup window, even near the rollover.
    let remaining = UDP_DEDUP_NS - monotonic_ns() % UDP_DEDUP_NS;
    if remaining < 1_000_000_000 {
        tokio::time::sleep(Duration::from_nanos(remaining)).await;
    }
    sendmsg_udp(&udp, destination);
    let second_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..2000 {
        second_udp.send_to(&[0], destination).unwrap();
    }
    udp6.send_to(&[0], peer6.local_addr().unwrap()).unwrap();
    let dual_stack = UdpSocket::bind("[::]:0").unwrap();
    dual_stack
        .send_to(
            &[0],
            (destination.ip().to_ipv6_mapped(), destination.port()),
        )
        .unwrap();

    // A connected UDP socket can supply an explicit per-send destination.
    // The send still belongs to the connected socket and must be filtered.
    udp.connect(destination).unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.send_to(&[0], other.local_addr().unwrap()).unwrap();

    let packet_proto = i32::from(3u16.to_be());
    drop(open_socket(libc::AF_PACKET, libc::SOCK_DGRAM, packet_proto).unwrap());
    drop(open_socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP).unwrap());
    assert!(open_socket(libc::AF_INET, libc::SOCK_RAW, -1).is_err());

    let mut capture = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if let RawPayload::Network(fields) = event.payload {
            capture.push((event.pid, event.action, fields));
        }
    }
    // Identify the test's kernel TGID using the listener's ephemeral port.
    let pid = capture
        .iter()
        .find_map(|(pid, action, fields)| {
            (*action == SensorAction::Listen
                && fields.source_ip.as_deref() == Some("127.0.0.1")
                && fields.source_port.as_deref() == Some(listen_port.as_str()))
            .then_some(*pid)
            .flatten()
        })
        .unwrap_or_else(|| panic!("listener event missing: {:?}", sensor.telemetry()));

    let mut listen_count = 0;
    let mut udp4_count = 0;
    let mut udp6_count = 0;
    let mut raw_protocols = Vec::new();
    for (event_pid, action, fields) in capture {
        if event_pid != Some(pid) {
            continue;
        }
        match action {
            SensorAction::Listen => {
                assert_eq!(fields.source_ip.as_deref(), Some("127.0.0.1"));
                assert_eq!(fields.source_port.as_deref(), Some(listen_port.as_str()));
                assert_eq!(fields.protocol.as_deref(), Some("tcp"));
                assert!(fields.destination_ip.is_none());
                listen_count += 1;
            }
            SensorAction::UdpSend => match fields.destination_ip.as_deref() {
                Some("127.0.0.1") => {
                    assert_eq!(fields.destination_port.as_deref(), Some(udp_port.as_str()));
                    udp4_count += 1;
                }
                Some("::1") => {
                    assert_eq!(fields.destination_port.as_deref(), Some(udp6_port.as_str()));
                    udp6_count += 1;
                }
                other => panic!("unexpected UDP destination: {other:?}"),
            },
            SensorAction::RawSocket => raw_protocols.push(fields.protocol.unwrap()),
            _ => {}
        }
    }
    assert_eq!(
        (listen_count, udp4_count, udp6_count),
        (1, 1, 1),
        "pid: {pid}, raw protocols: {raw_protocols:?}, telemetry: {:?}",
        sensor.telemetry().unwrap().families
    );
    raw_protocols.sort_unstable();
    assert_eq!(raw_protocols, ["ethertype:0x0003", "icmp"]);

    // Different destinations evade tuple dedup but share the same kernel budget.
    let (start_window, end_window) = tokio::task::spawn_blocking(|| {
        let start = monotonic_ns() / UDP_BUDGET_NS;
        std::thread::scope(|scope| {
            for range in (40_000..44_096).step_by(1024) {
                scope.spawn(move || {
                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                    for port in range..range + 1024 {
                        socket
                            .send_to(&[0; 16], (Ipv4Addr::LOCALHOST, port))
                            .unwrap();
                    }
                });
            }
        });
        (start, monotonic_ns() / UDP_BUDGET_NS)
    })
    .await
    .unwrap();
    let limit = (end_window - start_window + 1) * UDP_EVENTS_PER_WINDOW;
    let mut churn_events = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if event.pid == Some(pid) && event.action == SensorAction::UdpSend {
            churn_events += 1;
        }
    }
    let snapshot = sensor.telemetry().unwrap();
    let network = snapshot
        .families
        .iter()
        .find(|f| f.ring == "network")
        .unwrap();
    println!("UDP churn submitted {churn_events}/4096 sends, budget {limit} across {} window(s), {network:?}",
        end_window - start_window + 1);
    assert!((1..=limit).contains(&churn_events));
    assert!(network.kernel_deduplicated >= 2002, "{network:?}");
    assert!(network.kernel_rate_limited > 0, "{network:?}");
    assert_eq!(network.kernel_ring_full, 0, "{network:?}");
    assert_eq!(network.kernel_read_errors, 0, "{network:?}");
    assert!(network.kernel_is_reconciled(), "{network:?}");
    sensor.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires eBPF privileges and BTF hidden inside a private mount namespace"]
async fn live_without_socket_btf_uses_syscall_fallback() {
    assert!(rustinel::sensor::linux::task_btf::SocketLayout::load().is_err());
    let ip = local_ip();
    let listener = TcpListener::bind((ip, 0)).unwrap();
    let server = listener.local_addr().unwrap();
    let sensor = EbpfSensor::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    sensor.start(tx).unwrap();
    let snapshot = sensor.telemetry().unwrap();
    assert!(snapshot
        .features
        .iter()
        .any(|f| f.feature == "network" && f.active));
    assert!(snapshot
        .features
        .iter()
        .any(|f| f.feature == "network_tuple" && !f.active));
    drop(open_socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP).unwrap());
    let stream = TcpStream::connect(server).unwrap();
    let accepted = listener.accept().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let server_port = server.port().to_string();
    let mut raw_pids = std::collections::HashSet::new();
    let mut connect_pid = None;
    while connect_pid.is_none_or(|pid| !raw_pids.contains(&pid)) {
        let event = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("connect fallback or raw socket event missing")
            .unwrap();
        let RawPayload::Network(fields) = event.payload else {
            continue;
        };
        if event.action == SensorAction::RawSocket && fields.protocol.as_deref() == Some("icmp") {
            raw_pids.insert(event.pid.unwrap());
        } else if event.action == SensorAction::Connect
            && fields.destination_port.as_deref() == Some(server_port.as_str())
        {
            assert_eq!(fields.initiated, Some(true));
            assert!(fields.source_ip.is_none());
            assert!(fields.source_port.is_none());
            assert!(fields.protocol.is_none());
            connect_pid = event.pid;
        }
    }
    drop((stream, accepted));
    sensor.shutdown();
}
