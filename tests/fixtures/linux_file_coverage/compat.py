"""Measure process and network fields from ordinary 32-bit Linux programs."""

import json
import socket
import subprocess


def exchange(args, serve):
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            serve()
            stdout, stderr = child.communicate(timeout=10)
            assert child.returncode == 0, (args, child.returncode, stderr)
            return child.pid, stdout
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def run(busybox):
    interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show", "scope", "global"]))
    address = next(entry["local"] for interface in interfaces for entry in interface["addr_info"])
    with socket.socket() as http:
        http.bind((address, 0))
        http.listen()
        http.settimeout(5)

        def serve_http():
            connection, _ = http.accept()
            with connection:
                connection.settimeout(5)
                assert connection.recv(4096).startswith(b"GET ")
                connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")

        port = http.getsockname()[1]
        tcp_pid, body = exchange(
            [str(busybox), "wget", "-q", "-Y", "off", "-O", "-", f"http://{address}:{port}/"],
            serve_http,
        )
        assert body == b"ok", body

    name = "rustinel-ci.test"
    answer = "192.0.2.41"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        # Use a dedicated loopback address alongside the runner's resolver.
        resolver = "127.0.0.77"
        dns.bind((resolver, 53))
        dns.settimeout(5)

        def serve_dns():
            query, peer = dns.recvfrom(512)
            question = b"\x0brustinel-ci\x04test\x00\x00\x01\x00\x01"
            assert query[12:].startswith(question), query.hex()
            header = query[:2] + bytes.fromhex("8180 0001 0001 0000 0000")
            record = bytes.fromhex("c00c 0001 0001 00000000 0004") + socket.inet_aton(answer)
            dns.sendto(header + question + record, peer)

        dns_pid, output = exchange(
            [str(busybox), "nslookup", "-type=A", name, resolver], serve_dns,
        )
        assert answer.encode() in output, output

    with subprocess.Popen([str(busybox), "sh", "-c", 'exec "$1" sleep 1', "sh", str(busybox)]) as process:
        assert process.wait(timeout=5) == 0
        exec_pid = process.pid

    return {
        "connect": ("Network", str(tcp_pid), "DestinationPort", str(port)),
        "DNS": ("Dns", str(dns_pid), "QueryName", name),
        "exec": ("Process", str(exec_pid), "CommandLine", "sleep 1"),
    }


def compare(events, expected):
    observed = dict.fromkeys(expected)
    for event in events:
        fields = event.get("fields", {})
        for name, (category, pid, field, value) in expected.items():
            if event.get("category") != category or fields.get("ProcessId") != pid:
                continue
            actual = fields.get(field) or ""
            if actual == value or (name == "exec" and actual.endswith(f" {value}")):
                observed[name] = actual
    return observed
