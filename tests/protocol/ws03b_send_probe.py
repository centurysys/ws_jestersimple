#!/usr/bin/env python3
"""WS-03b wire-level send serialization, deadline and cleanup tests."""
import argparse
import concurrent.futures
import os
import socket
import struct
import time

HOST = "127.0.0.1"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def take(sock, n, carry=b""):
    buf = bytearray(carry)
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        assert chunk, f"early EOF {len(buf)}/{n}"
        buf.extend(chunk)
    return bytes(buf[:n]), bytes(buf[n:])


def upgrade(port, path):
    sock = socket.create_connection((HOST, port), timeout=4)
    sock.settimeout(5)
    request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: Upgrade\r\nUpgrade: websocket\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               f"Sec-WebSocket-Key: {KEY}\r\n\r\n")
    sock.sendall(request.encode("ascii"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        assert chunk, "HTTP handshake ended early"
        response.extend(chunk)
        assert len(response) < 32768
    head, carry = bytes(response).split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.1 101 "), head
    assert (b"sec-websocket-accept: " + ACCEPT.lower()) in head.lower(), head
    return sock, carry


def frame_read(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    opcode = header[0] & 15
    assert not (header[1] & 0x80), "server frame unexpectedly masked"
    size = header[1] & 127
    if size == 126:
        ext, carry = take(sock, 2, carry)
        size = struct.unpack("!H", ext)[0]
    elif size == 127:
        ext, carry = take(sock, 8, carry)
        size = struct.unpack("!Q", ext)[0]
    assert size <= 8 * 1024 * 1024, f"unexpected payload size {size}"
    data, carry = take(sock, size, carry)
    return opcode, data, carry


def frame_send(sock, opcode, payload=b""):
    mask = b"\x21\x43\x65\x87"
    result = bytearray([0x80 | opcode])
    size = len(payload)
    if size <= 125:
        result.append(0x80 | size)
    elif size <= 65535:
        result.append(0x80 | 126)
        result.extend(struct.pack("!H", size))
    else:
        result.append(0x80 | 127)
        result.extend(struct.pack("!Q", size))
    result.extend(mask)
    result.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    sock.sendall(result)


def assert_closed(sock, carry=b""):
    assert not carry, f"unexpected trailing data: {carry[:32]!r}"
    sock.settimeout(3)
    assert sock.recv(1) == b"", "expected EOF after Close handshake"


def http_stats(port):
    with socket.create_connection((HOST, port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(b"GET /stats HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = bytearray()
        while True:
            buf = sock.recv(4096)
            if not buf:
                break
            data.extend(buf)
        return tuple(int(x) for x in bytes(data).split(b"\r\n\r\n", 1)[1].strip().split(b","))


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def rss_kib(pid):
    for line in open(f"/proc/{pid}/status", encoding="ascii"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise AssertionError("VmRSS missing")


def test_concurrent_frames(port):
    sock, carry = upgrade(port, "/concurrent")
    with sock:
        for letter, length in ((b"A", 1024 * 1024 + 101),
                               (b"B", 1024 * 1024 + 203)):
            opcode, data, carry = frame_read(sock, carry)
            assert opcode == 1 and data == letter * length, (opcode, len(data))
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (1, b"tail")
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (8, b"")
        frame_send(sock, 8)
        assert_closed(sock, carry)


def test_close_order(port):
    sock, carry = upgrade(port, "/close-order")
    with sock:
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 1 and data == b"Q" * (1024 * 1024 + 111)
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (8, b"")
        frame_send(sock, 8)
        assert_closed(sock, carry)


def test_ping_order(port):
    sock, carry = upgrade(port, "/ping-order")
    with sock:
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 1 and data == b"P" * (1024 * 1024 + 131)
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (9, b"ordered")
        frame_send(sock, 10, data)
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 8
        frame_send(sock, 8)
        assert_closed(sock, carry)


def test_queue_overlap(port):
    before = http_stats(port)
    sock, carry = upgrade(port, "/queue-overlap")
    with sock:
        for letter, length in ((b"C", 1024 * 1024 + 101),
                               (b"D", 1024 * 1024 + 203)):
            opcode, data, carry = frame_read(sock, carry)
            assert opcode == 1 and data == letter * length
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 8
        frame_send(sock, 8)
        assert_closed(sock, carry)
    after = http_stats(port)
    assert after[1] == before[1] + 1, (before, after)


def test_queue_limit(port):
    before = http_stats(port)
    sock, carry = upgrade(port, "/limit")
    with sock:
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (1, b"limit-ok")
        frame_send(sock, 8)
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 8
        assert_closed(sock, carry)
    after = http_stats(port)
    assert after[1] == before[1] + 1, (before, after)


def test_config(port):
    sock, carry = upgrade(port, "/config")
    with sock:
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (1, b"5")
        frame_send(sock, 8)
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 8
        assert_closed(sock, carry)


def echo_once(port, text):
    sock, carry = upgrade(port, "/echo")
    with sock:
        frame_send(sock, 1, text.encode("utf-8"))
        opcode, data, carry = frame_read(sock, carry)
        assert (opcode, data) == (1, text.encode("utf-8"))
        frame_send(sock, 8)
        opcode, data, carry = frame_read(sock, carry)
        assert opcode == 8 and data == b""
        assert_closed(sock, carry)


def test_parallel_connections(port):
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(echo_once, port, f"client-{i}") for i in range(36)]
        for future in futures:
            future.result(timeout=20)


def test_slow_reader_timeout(port):
    before = http_stats(port)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(3)
    sock.connect((HOST, port))
    try:
        request = (f"GET /slow-reader HTTP/1.1\r\nHost: localhost\r\n"
                   "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   f"Sec-WebSocket-Key: {KEY}\r\n\r\n")
        sock.sendall(request.encode("ascii"))
        # Do not read while the server attempts to write a 6 MiB frame.
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if http_stats(port)[0] > before[0]:
                break
            time.sleep(.06)
        else:
            raise AssertionError("write timeout not observed for a stalled client")
    finally:
        sock.close()


def test_fd_rss_recovery(port, pid):
    start_fd = fd_count(pid)
    start_rss = rss_kib(pid)
    for i in range(40):
        echo_once(port, f"cycle-{i}")
    until = time.monotonic() + 3
    while fd_count(pid) > start_fd + 3 and time.monotonic() < until:
        time.sleep(.05)
    final_fd = fd_count(pid)
    final_rss = rss_kib(pid)
    assert final_fd <= start_fd + 3, (start_fd, final_fd)
    # A high-watermark allocator may retain large frame buffers by design.
    assert final_rss <= start_rss + 64 * 1024, (start_rss, final_rss)
    print(f"RESOURCE FD {start_fd}->{final_fd}, RSS {start_rss}->{final_rss} KiB")


def test_server_healthy(port):
    assert http_stats(port)[2] == 0, http_stats(port)
    echo_once(port, "still-alive")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_concurrent_frames, test_close_order, test_ping_order,
             test_queue_overlap, test_queue_limit,
             test_config, test_parallel_connections, test_slow_reader_timeout,
             lambda port: test_fd_rss_recovery(port, args.pid), test_server_healthy)
    for test in tests:
        started = time.monotonic()
        test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - started:.3f}s)", flush=True)
    print(f"WS-03b {args.mode} {len(tests)}/{len(tests)} PASS", flush=True)


if __name__ == "__main__":
    main()
