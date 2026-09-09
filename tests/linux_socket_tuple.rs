#![cfg(target_os = "linux")]

use rustinel::sensor::{linux::EbpfSensor, Sensor, SensorPayload};
use std::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires runtime kernel BTF"]
fn running_kernel_socket_layout() {
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
    let snapshot = rustinel::telemetry::LINUX_EBPF.snapshot().unwrap();
    assert!(
        snapshot
            .features
            .iter()
            .any(|f| f.feature == "network_tuple" && f.active),
        "{snapshot:?}"
    );

    udp.connect(server).unwrap();
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
    let mut saw_udp = false;
    let mut max_delay = Duration::ZERO;
    let pid = std::process::id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while outbound + inbound < count * 2 || !saw_udp {
        let event = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("drain stalled or lost connection events")
            .unwrap();
        if event.pid != Some(pid) {
            continue;
        }
        let SensorPayload::Network(fields) = event.payload else {
            continue;
        };
        max_delay = max_delay.max(event.timestamp.elapsed().unwrap_or_default());
        assert_eq!(fields.source_ip.as_deref(), Some(ip.to_string().as_str()));
        assert_eq!(
            fields.destination_ip.as_deref(),
            Some(ip.to_string().as_str())
        );
        if fields.protocol.as_deref() == Some("udp") {
            assert_eq!(
                fields.source_port.as_deref(),
                Some(udp_source.port().to_string().as_str())
            );
            saw_udp = true;
        } else {
            assert_eq!(fields.protocol.as_deref(), Some("tcp"));
            assert!(fields.source_port.is_some());
            if fields.initiated == Some(true) {
                assert_eq!(
                    fields.destination_port.as_deref(),
                    Some(server.port().to_string().as_str())
                );
                outbound += 1;
            } else {
                // Incoming source is the peer, destination is the listener.
                assert_eq!(
                    fields.destination_port.as_deref(),
                    Some(server.port().to_string().as_str())
                );
                inbound += 1;
            }
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
        if event.pid == Some(pid) {
            assert!(
                !matches!(event.payload, SensorPayload::Network(_)),
                "loopback leaked to ring"
            );
        }
    }
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
    let snapshot = rustinel::telemetry::LINUX_EBPF.snapshot().unwrap();
    assert!(snapshot
        .features
        .iter()
        .any(|f| f.feature == "network" && f.active));
    assert!(snapshot
        .features
        .iter()
        .any(|f| f.feature == "network_tuple" && !f.active));
    let stream = TcpStream::connect(server).unwrap();
    let accepted = listener.accept().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap()
            .unwrap();
        if event.pid != Some(std::process::id()) {
            continue;
        }
        let SensorPayload::Network(fields) = event.payload else {
            continue;
        };
        assert_eq!(
            fields.destination_port.as_deref(),
            Some(server.port().to_string().as_str())
        );
        assert_eq!(fields.initiated, Some(true));
        assert!(fields.source_ip.is_none());
        assert!(fields.source_port.is_none());
        assert!(fields.protocol.is_none());
        break;
    }
    drop((stream, accepted));
    sensor.shutdown();
}
