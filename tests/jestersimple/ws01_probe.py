#!/usr/bin/env python3
"""WS-01 loopback tests: RFC 6455 handshake, echo, rejection and FD release.

Do not use this as a general WebSocket protocol conformance test; recvExact,
size limits, proper close handshake and ping handling are later work items.
"""
import argparse
import os
import socket
import time

HOST = "127.0.0.1"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MASK = bytes([0x21, 0x43, 0x65, 0x87])


def connect(port):
    sock = socket.create_connection((HOST, port), timeout=2.0)
    sock.settimeout(2.0)
    return sock


def request(sock, path="/ws", method="GET", version="HTTP/1.1",
            headers=()):
    lines = [f"{method} {path} {version}", "Host: localhost"]
    lines += list(headers)
    if method == "POST":
        lines.append("Content-Length: 0")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))


def upgrade_headers(*extra):
    return ("Connection: keep-alive, UpGrAdE", "Upgrade: WebSocket",
            "Sec-WebSocket-Version: 13", f"Sec-WebSocket-Key: {KEY}", *extra)


def read_header(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        packet = sock.recv(4096)
        assert packet, "EOF while reading HTTP headers"
        data.extend(packet)
        assert len(data) < 16384, "HTTP headers too large"
    head, carry = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    fields = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        fields.setdefault(name.lower(), []).append(value.strip())
    return status, fields, carry


def read_body(sock, fields, carry):
    length = int(fields.get(b"content-length", [b"0"])[0])
    while len(carry) < length:
        packet = sock.recv(length - len(carry))
        assert packet, "EOF while reading HTTP response body"
        carry += packet
    return carry[:length], carry[length:]


def take(sock, length, carry=b""):
    data = bytearray(carry)
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        assert chunk, "EOF while reading WebSocket frame"
        data.extend(chunk)
    return bytes(data[:length]), bytes(data[length:])


def client_frame(opcode, payload=b""):
    assert len(payload) <= 125  # WS-01 deliberately uses short frames only.
    output = bytes([0x80 | opcode, 0x80 | len(payload)]) + MASK
    output += bytes(c ^ MASK[i % 4] for i, c in enumerate(payload))
    return output


def read_frame(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    assert not (header[1] & 0x80), "server frames must not be masked"
    n = header[1] & 0x7F
    assert n <= 125, "WS-01 response unexpectedly used extended length"
    payload, carry = take(sock, n, carry)
    return header[0] & 0x0F, payload, carry


def assert_eof(sock):
    try:
        data = sock.recv(4096)
    except ConnectionResetError:
        return
    assert data == b"", f"expected EOF, got {data!r}"


def open_ws(port, path="/ws", headers=None):
    sock = connect(port)
    try:
        request(sock, path, headers=upgrade_headers() if headers is None else headers)
        status, fields, carry = read_header(sock)
        assert status == 101, (status, fields)
        assert fields[b"sec-websocket-accept"] == [ACCEPT.encode()]
        assert fields[b"connection"] == [b"Upgrade"]
        assert fields[b"upgrade"][0].lower() == b"websocket"
        assert carry == b"", f"unexpected bytes after 101: {carry!r}"
        return sock, fields
    except BaseException:
        sock.close()
        raise


def test_normal_http(port):
    with connect(port) as sock:
        request(sock, "/ping", headers=("Connection: close",))
        status, fields, carry = read_header(sock)
        assert status == 200
        body, carry = read_body(sock, fields, carry)
        assert (body, carry) == (b"pong", b"")
        assert_eof(sock)


def test_echo(port):
    with open_ws(port)[0] as sock:
        time.sleep(0.2)  # Must remain usable after HTTP 101.
        for opcode, data in ((1, b"hello-ws01"), (2, b"\x00\x01binary")):
            sock.sendall(client_frame(opcode, data))
            got_opcode, got_data, remain = read_frame(sock)
            assert (got_opcode, got_data, remain) == (opcode, data, b"")
        # ws 0.6.0 currently does NOT send a Close response; WS-02a fixes it.
        sock.sendall(client_frame(8))
        assert_eof(sock)


def test_protocol(port):
    sock, fields = open_ws(port, "/ws", upgrade_headers("Sec-WebSocket-Protocol: chat, superchat"))
    assert b"sec-websocket-protocol" not in fields
    with sock:
        sock.sendall(client_frame(1, b"no-selection"))
        assert read_frame(sock)[:2] == (1, b"no-selection")
        sock.sendall(client_frame(8))
        assert_eof(sock)

    sock, fields = open_ws(port, "/ws-protocol", upgrade_headers("Sec-WebSocket-Protocol: superchat, chat"))
    assert fields[b"sec-websocket-protocol"] == [b"chat"]
    with sock:
        sock.sendall(client_frame(1, b"selected"))
        assert read_frame(sock)[:2] == (1, b"selected")
        assert_eof(sock)


def test_rejected(port):
    cases = [
        ("missing-upgrade", "/ws", "GET", "HTTP/1.1",
         ("Connection: close", f"Sec-WebSocket-Key: {KEY}", "Sec-WebSocket-Version: 13")),
        ("missing-connection", "/ws", "GET", "HTTP/1.1",
         ("Upgrade: websocket", f"Sec-WebSocket-Key: {KEY}", "Sec-WebSocket-Version: 13")),
        ("bad-version", "/ws", "GET", "HTTP/1.1",
         upgrade_headers()[:-2] + ("Sec-WebSocket-Version: 12", f"Sec-WebSocket-Key: {KEY}")),
        ("bad-key", "/ws", "GET", "HTTP/1.1",
         upgrade_headers()[:-1] + ("Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAA?==",)),
        ("duplicate-key", "/ws", "GET", "HTTP/1.1",
         upgrade_headers() + (f"Sec-WebSocket-Key: {KEY}",)),
        ("duplicate-version", "/ws", "GET", "HTTP/1.1",
         upgrade_headers() + ("Sec-WebSocket-Version: 13",)),
        ("duplicate-offer", "/ws", "GET", "HTTP/1.1",
         upgrade_headers("Sec-WebSocket-Protocol: chat",
                         "Sec-WebSocket-Protocol: other")),
        ("malformed-key", "/ws", "GET", "HTTP/1.1",
         upgrade_headers()[:-1] + ("Sec-WebSocket-Key: abc",)),
        ("bad-offer", "/ws", "GET", "HTTP/1.1",
         upgrade_headers("Sec-WebSocket-Protocol: chat, , other")),
        ("not-offered", "/ws-protocol", "GET", "HTTP/1.1",
         upgrade_headers("Sec-WebSocket-Protocol: other")),
        ("http10", "/ws", "GET", "HTTP/1.0", upgrade_headers()),
        ("post", "/ws", "POST", "HTTP/1.1", upgrade_headers()),
        ("invalid-header-control", "/ws", "GET", "HTTP/1.1",
         upgrade_headers("X-Injected: bad\x01value")),
    ]
    for name, path, method, version, headers in cases:
        with connect(port) as sock:
            request(sock, path, method, version, headers)
            status, _, _ = read_header(sock)
            assert status != 101 and 400 <= status < 500, (name, status)


def test_fault(port):
    with open_ws(port, "/ws-fault")[0] as sock:
        assert_eof(sock)  # No extra HTTP 500 after HTTP 101.
    test_normal_http(port)


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def test_fd_cycles(port, pid):
    baseline = fd_count(pid)
    for _ in range(20):
        with open_ws(port)[0] as sock:
            sock.sendall(client_frame(8))
            assert_eof(sock)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and fd_count(pid) > baseline + 2:
        time.sleep(0.03)
    assert fd_count(pid) <= baseline + 2, (baseline, fd_count(pid))


def test_slots(port):
    first, _ = open_ws(port)
    second, _ = open_ws(port)
    try:
        with connect(port) as sock:
            request(sock, "/ping")
            assert_eof(sock)  # Two WebSockets fill maxConnections=2.
        first.close()
        # Closing a client releases the server's connection slot.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                test_normal_http(port)
                break
            except (OSError, AssertionError):
                time.sleep(0.04)
        else:
            raise AssertionError("connection slot not released")
        second.sendall(client_frame(1, b"alive"))
        assert read_frame(second)[:2] == (1, b"alive")
    finally:
        first.close()
        second.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_normal_http, test_echo, test_protocol, test_rejected,
             test_fault, test_fd_cycles, test_slots)
    for test in tests:
        start = time.monotonic()
        if test in (test_fd_cycles,):
            test(args.port, args.pid)
        else:
            test(args.port)
        print(f"PASS {args.mode}: {test.__name__} ({time.monotonic()-start:.3f}s)", flush=True)
    print(f"WS-01 {args.mode} 7/7 PASS", flush=True)


if __name__ == "__main__":
    main()
