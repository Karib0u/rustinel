#!/usr/bin/env python3
"""Lab fixture for Linux DNS capture (issue 804).

Run as root next to a live `rustinel capture`. It starts a fake resolver on
127.0.0.1:53 (UDP and TCP), then issues one query per carrier. Every case uses
its own name, so `--check <recording>` can say which carriers were captured.

    sudo python3 tests/linux_dns_fixture.py run
    sudo python3 tests/linux_dns_fixture.py check <recording.ndjson>
    sudo python3 tests/linux_dns_fixture.py serve   # for dig and other real clients

`run` prints the case names; `check` expects each as a query, and as a
response where the carrier reads one back.
"""

import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time

ANSWER_IP = bytes([192, 0, 2, 53])
SYS_RECVMMSG = {"x86_64": 299, "aarch64": 243}[os.uname().machine]
LONG_LABEL = "a" * 63


def long_name():
    """A 253-character name, the longest a resolver sends (255 bytes on the wire)."""
    name = ".".join([LONG_LABEL] * 3 + ["b" * 48 + ".fixture.test"])
    assert len(name) == 253
    return name


def oversized_name():
    """Eight 63-byte labels: 520 bytes on the wire, past the sensor's 512-byte capture."""
    return ".".join(["oversized-" + "a" * 53] + ["c" * 63] * 7)


def encode(name, response=False, txid=0x1234):
    flags = 0x8180 if response else 0x0100
    msg = struct.pack(">HHHHHH", txid, flags, 1, 1 if response else 0, 0, 0)
    for label in name.split("."):
        msg += bytes([len(label)]) + label.encode()
    msg += b"\x00" + struct.pack(">HH", 1, 1)
    if response:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ANSWER_IP
    return msg


def serve_udp(stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 53))
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        sock.sendto(echo(data), peer)
    sock.close()


def echo(query):
    """Answer a query by flipping the QR bit and appending one A record."""
    end = 12
    while query[end]:
        end += query[end] + 1
    end += 5
    head = struct.pack(">HHHHHH", struct.unpack(">H", query[:2])[0], 0x8180, 1, 1, 0, 0)
    return head + query[12:end] + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ANSWER_IP


def serve_tcp(stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 53))
    srv.listen(8)
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        with conn:
            raw = conn.recv(4096)
            if len(raw) > 2:
                reply = echo(raw[2:])
                conn.sendall(struct.pack(">H", len(reply)) + reply)
    srv.close()


class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class MsgHdr(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32),
        ("iov", ctypes.POINTER(IoVec)), ("iovlen", ctypes.c_size_t),
        ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
        ("flags", ctypes.c_int),
    ]


class MmsgHdr(ctypes.Structure):
    _fields_ = [("hdr", MsgHdr), ("len", ctypes.c_uint)]


def recvmmsg(sock):
    """Receive one datagram with recvmmsg(2); Python has no wrapper."""
    libc = ctypes.CDLL(None, use_errno=True)
    # A socket with a Python timeout is non-blocking; recvmmsg needs a blocking one.
    sock.settimeout(None)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 2, 0))
    buf = ctypes.create_string_buffer(2048)
    iov = IoVec(ctypes.cast(buf, ctypes.c_void_p), len(buf))
    vec = (MmsgHdr * 1)()
    vec[0].hdr.iov = ctypes.pointer(iov)
    vec[0].hdr.iovlen = 1
    got = libc.syscall(SYS_RECVMMSG, sock.fileno(), vec, 1, 0, None)
    if got < 1:
        raise OSError(ctypes.get_errno(), "recvmmsg")
    return buf.raw[: vec[0].len]


def udp_case(name, receiver):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(encode(name), ("127.0.0.1", 53))
    receiver(sock)
    sock.close()


def tcp_connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", 53))
    return sock


def case_tcp_write(name):
    sock = tcp_connect()
    msg = encode(name)
    sock.send(struct.pack(">H", len(msg)) + msg)  # one buffer, as the Go resolver writes it
    sock.recv(4096)
    sock.close()


def case_tcp_sendmsg_split(name):
    sock = tcp_connect()
    msg = encode(name)
    sock.sendmsg([struct.pack(">H", len(msg)), msg])  # length then message, as BIND and dig send it
    sock.recv(4096)
    sock.close()


def cases():
    return [
        ("udp-recvfrom", "udp-recvfrom.fixture.test", lambda n: udp_case(n, lambda s: s.recvfrom(4096))),
        ("udp-recvmmsg", "udp-recvmmsg.fixture.test", lambda n: udp_case(n, recvmmsg)),
        ("udp-long", long_name(), lambda n: udp_case(n, lambda s: s.recvfrom(4096))),
        ("udp-oversized", oversized_name(), lambda n: udp_case(n, lambda s: s.recvfrom(4096))),
        ("tcp-write", "tcp-write.fixture.test", case_tcp_write),
        ("tcp-sendmsg-split", "tcp-sendmsg-split.fixture.test", case_tcp_sendmsg_split),
    ]


def run():
    stop = threading.Event()
    threads = [threading.Thread(target=f, args=(stop,)) for f in (serve_udp, serve_tcp)]
    for thread in threads:
        thread.start()
    time.sleep(0.5)
    try:
        for label, name, fn in cases():
            try:
                fn(name)
            except OSError as error:
                print(f"{label} carrier failed: {error}", flush=True)
            print(f"{label} {name}", flush=True)
            time.sleep(0.3)
    finally:
        stop.set()
        for thread in threads:
            thread.join()


def serve():
    """Answer on 127.0.0.1:53 until interrupted, for real clients such as dig."""
    stop = threading.Event()
    threads = [threading.Thread(target=f, args=(stop,)) for f in (serve_udp, serve_tcp)]
    for thread in threads:
        thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def check(path):
    """Print which cases reached the recording; exit 1 when one is missing."""
    lines = open(path).read().splitlines()
    missing = 0
    for label, name, _ in cases():
        needle = name.split(".")[0] if label == "udp-oversized" else name
        rows = [line for line in lines if needle in line]
        queries = [r for r in rows if '"query_results"' not in r and 'QueryResults' not in r]
        responses = [r for r in rows if 'QueryResults' in r or '"query_results"' in r]
        ok = bool(queries)
        if label == "udp-oversized":
            ok = ok and any("QueryTruncated" in row for row in queries)
        missing += not ok
        print(f"{label:20} query={len(queries)} response={len(responses)} {'ok' if ok else 'MISSING'}")
        for row in rows[:1]:
            print("   ", json.dumps(json.loads(row))[:400] if row.startswith("{") else row[:400])
    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "run":
        run()
    elif len(sys.argv) == 2 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        sys.exit(__doc__)
