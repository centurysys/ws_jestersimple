#!/usr/bin/env python3
"""WS-02a loopback tests for Close frame ordering and socket cleanup.

Uses short, unfragmented frames. Exact TCP reads, long frames and malformed
frame validation belong to subsequent WS-02b/02c/02d stages.
"""
import argparse
import os
import socket
import time

HOST = "127.0.0.1"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MASK = b"\x12\x34\x56\x78"


def connect(port):
    sock = socket.create_connection((HOST, port), timeout=2.0)
    sock.settimeout(2.0)
    return sock


def take(sock, count, carry=b""):
    data = bytearray(carry)
    while len(data) < count:
        packet = sock.recv(count - len(data))
        assert packet, "unexpected EOF"
        data.extend(packet)
    return bytes(data[:count]), bytes(data[count:])


def upgrade(port, path):
    sock = connect(port)
    request = (f"GET {path} HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Connection: Upgrade\r\n"
               "Upgrade: websocket\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               f"Sec-WebSocket-Key: {KEY}\r\n\r\n")
    try:
        sock.sendall(request.encode("ascii"))
        head = bytearray()
        while b"\r\n\r\n" not in head:
            fragment = sock.recv(4096)
            assert fragment, "EOF during HTTP handshake"
            head.extend(fragment)
            assert len(head) < 16384, "oversized HTTP handshake"
        header, carry = bytes(head).split(b"\r\n\r\n", 1)
        assert header.startswith(b"HTTP/1.1 101 "), header
        # HTTP field names are case-insensitive, but the Base64 value is not.
        accept_values = [
            line.partition(b":")[2].strip()
            for line in header.split(b"\r\n")[1:]
            if line.partition(b":")[0].strip().lower() == b"sec-websocket-accept"
        ]
        assert accept_values == [ACCEPT], header
        return sock, carry
    except BaseException:
        sock.close()
        raise


def client_close(payload=b""):
    assert len(payload) <= 125
    return (bytes((0x88, 0x80 | len(payload))) + MASK +
            bytes(c ^ MASK[i % 4] for i, c in enumerate(payload)))


def read_close(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    assert header[0] == 0x88, f"expected FIN+Close, got {header[0]:#x}"
    assert not (header[1] & 0x80), "server must not mask Close"
    size = header[1] & 0x7f
    assert size <= 125, f"invalid Close length marker: {size}"
    payload, carry = take(sock, size, carry)
    return payload, carry


def assert_eof(sock, carry=b""):
    assert carry == b"", f"unexpected bytes after Close: {carry!r}"
    try:
        data = sock.recv(4096)
    except ConnectionResetError:
        return
    assert data == b"", f"unexpected bytes after Close: {data!r}"


def test_peer_close(port):
    # Code 1000 followed by a short UTF-8 reason; reply should echo payload.
    payload = b"\x03\xe8ok"
    sock, carry = upgrade(port, "/peer-close")
    with sock:
        sock.sendall(client_close(payload))
        reply, carry = read_close(sock, carry)
        assert reply == payload, reply
        assert_eof(sock, carry)


def test_server_close(port):
    sock, carry = upgrade(port, "/server-close")
    with sock:
        payload, carry = read_close(sock, carry)
        assert payload == b""
        sock.sendall(client_close())
        assert_eof(sock, carry)


def test_duplicate_close(port):
    sock, carry = upgrade(port, "/duplicate-close")
    with sock:
        payload, carry = read_close(sock, carry)
        assert payload == b""
        sock.sendall(client_close())
        assert_eof(sock, carry)  # A second Close frame would fail here.


def test_no_reply(port):
    sock, carry = upgrade(port, "/no-reply")
    with sock:
        payload, carry = read_close(sock, carry)
        assert payload == b""
        # Do NOT send a Close reply: application must still release its FD.
        assert_eof(sock, carry)


def test_legacy_close(port):
    sock, carry = upgrade(port, "/legacy-close")
    with sock:
        payload, carry = read_close(sock, carry)
        assert payload == b""
        assert_eof(sock, carry)


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def test_fd_cycles(port, pid):
    baseline = fd_count(pid)
    for _ in range(30):
        test_peer_close(port)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and fd_count(pid) > baseline + 2:
        time.sleep(0.03)
    assert fd_count(pid) <= baseline + 2, (baseline, fd_count(pid))


def test_http_alive(port):
    with connect(port) as sock:
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                     b"Connection: close\r\n\r\n")
        data = bytearray()
        while b"\r\n\r\n" not in data or b"alive" not in data:
            part = sock.recv(4096)
            assert part, "EOF before health response body"
            data.extend(part)
            assert len(data) < 16384, "oversized health response"
        assert data.startswith(b"HTTP/1.1 200 "), data[:100]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_peer_close, test_server_close, test_duplicate_close,
             test_no_reply, test_legacy_close, test_fd_cycles, test_http_alive)
    for test in tests:
        start = time.monotonic()
        if test is test_fd_cycles:
            test(args.port, args.pid)
        else:
            test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - start:.3f}s)", flush=True)
    print(f"WS-02a {args.mode} {len(tests)}/{len(tests)} PASS", flush=True)


if __name__ == "__main__":
    main()
