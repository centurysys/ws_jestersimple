#!/usr/bin/env python3
"""WS-02b loopback tests: short TCP reads, EOF in every frame field.

No third-party Python dependencies. This intentionally uses well-formed,
masked RFC 6455 frames; malformed-frame validation is deferred to WS-02d.
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
    sock = socket.create_connection((HOST, port), timeout=3.0)
    sock.settimeout(3.0)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def take(sock, count, carry=b""):
    data = bytearray(carry)
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, f"unexpected EOF ({len(data)}/{count} bytes)"
        data.extend(chunk)
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
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            assert chunk, "EOF during HTTP handshake"
            data.extend(chunk)
            assert len(data) < 16384, "oversized handshake"
        header, carry = bytes(data).split(b"\r\n\r\n", 1)
        assert header.startswith(b"HTTP/1.1 101 "), header
        values = [line.partition(b":")[2].strip()
                  for line in header.split(b"\r\n")[1:]
                  if line.partition(b":")[0].strip().lower() ==
                  b"sec-websocket-accept"]
        assert values == [ACCEPT], header
        return sock, carry
    except BaseException:
        sock.close()
        raise


def client_frame(payload, opcode=1):
    length = len(payload)
    if length <= 125:
        ext = bytes([0x80 | length])
    elif length <= 65535:
        ext = b"\xfe" + length.to_bytes(2, "big")
    else:
        ext = b"\xff" + length.to_bytes(8, "big")
    return (bytes([0x80 | opcode]) + ext + MASK +
            bytes(value ^ MASK[i % 4] for i, value in enumerate(payload)))


def read_frame(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    assert header[0] & 0x80, "non-FIN response frame"
    assert not (header[1] & 0x80), "server illegally masked frame"
    length = header[1] & 0x7f
    if length == 126:
        raw, carry = take(sock, 2, carry)
        length = int.from_bytes(raw, "big")
    elif length == 127:
        raw, carry = take(sock, 8, carry)
        length = int.from_bytes(raw, "big")
    payload, carry = take(sock, length, carry)
    return header[0] & 0x0f, payload, carry


def send_split(sock, data, boundaries, delay=0.012):
    position = 0
    for end in boundaries:
        assert position < end < len(data), (position, end, len(data))
        sock.sendall(data[position:end])
        time.sleep(delay)
        position = end
    sock.sendall(data[position:])


def finish_echo(sock, carry=b""):
    sock.sendall(client_frame(b"", opcode=8))
    kind, payload, carry = read_frame(sock, carry)
    assert (kind, payload) == (8, b""), (kind, payload)
    assert_eof(sock, carry)


def assert_eof(sock, carry=b""):
    assert carry == b"", f"unexpected trailing bytes: {carry[:32]!r}"
    try:
        rest = sock.recv(4096)
    except ConnectionResetError:
        return
    assert rest == b"", f"expected EOF, got {rest[:32]!r}"


def echo_once(port, payload, boundaries):
    sock, carry = upgrade(port, "/echo")
    with sock:
        send_split(sock, client_frame(payload), boundaries)
        opcode, response, carry = read_frame(sock, carry)
        assert (opcode, response) == (1, payload), (opcode, len(response))
        finish_echo(sock, carry)


def test_split_fixed_mask_payload(port):
    # Separate the 2-byte base header, all mask octets and payload octets.
    echo_once(port, b"tcp-boundaries", list(range(1, 15)))


def test_split_extended16(port):
    payload = b"A" * 130
    # Header 2 bytes, extension 2 bytes, mask 4 bytes, then payload.
    echo_once(port, payload, list(range(1, 12)) + [16, 28, 41, 73])


def test_split_extended64(port):
    # The RFC-minimal length-127 encoding starts at 65536 bytes.
    payload = b"S" * 65536
    echo_once(port, payload, list(range(1, 17)) +
              [32, 160, 4096, 16384, 32768, 49152])


def test_empty_payload(port):
    echo_once(port, b"", [1, 2, 3, 4, 5])


def test_coalesced_frames(port):
    sock, carry = upgrade(port, "/echo")
    with sock:
        sock.sendall(client_frame(b"first") + client_frame(b"second"))
        kind, payload, carry = read_frame(sock, carry)
        assert (kind, payload) == (1, b"first")
        kind, payload, carry = read_frame(sock, carry)
        assert (kind, payload) == (1, b"second")
        finish_echo(sock, carry)


def http_body(port, path):
    with connect(port) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        header = bytearray()
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(4096)
            assert chunk, "EOF during HTTP response headers"
            header.extend(chunk)
            assert len(header) < 16384
        head, carry = bytes(header).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200 "), head
        lengths = [int(line.partition(b":")[2].strip())
                   for line in head.split(b"\r\n")[1:]
                   if line.partition(b":")[0].strip().lower() ==
                   b"content-length"]
        assert len(lengths) == 1, head
        body, carry = take(sock, lengths[0], carry)
        assert not carry, carry
        return body


def stats(port):
    parts = http_body(port, "/stats").split(b",")
    assert len(parts) == 3, parts
    return tuple(map(int, parts))


def truncated(port, data):
    before = stats(port)
    sock, carry = upgrade(port, "/eof")
    with sock:
        assert carry == b"", carry
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        assert_eof(sock)
    after = stats(port)
    assert after == (before[0] + 1, before[1] + 1, before[2]), (before, after)


def test_eof_fixed_header(port):
    truncated(port, client_frame(b"abc")[:1])


def test_eof_extended_lengths(port):
    truncated(port, client_frame(b"A" * 130)[:3])  # 1 of 2 ext bytes
    truncated(port, client_frame(b"X" * 65536)[:6])  # 4 of 8 ext bytes


def test_eof_mask_and_payload(port):
    frame = client_frame(b"payload")
    truncated(port, frame[:4])  # 2 of 4 mask bytes
    truncated(port, frame[:-2])  # incomplete payload
    truncated(port, client_frame(b"Z" * 65536)[:1038])


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def test_eof_fd_cycles(port, pid):
    baseline = fd_count(pid)
    frame = client_frame(b"partial")[:7]
    for _ in range(25):
        truncated(port, frame)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and fd_count(pid) > baseline + 2:
        time.sleep(0.02)
    assert fd_count(pid) <= baseline + 2, (baseline, fd_count(pid))


def test_http_alive(port):
    assert http_body(port, "/health") == b"alive"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_split_fixed_mask_payload, test_split_extended16,
             test_split_extended64, test_empty_payload, test_coalesced_frames,
             test_eof_fixed_header, test_eof_extended_lengths,
             test_eof_mask_and_payload, test_eof_fd_cycles, test_http_alive)
    for test in tests:
        start = time.monotonic()
        if test is test_eof_fd_cycles:
            test(args.port, args.pid)
        else:
            test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - start:.3f}s)", flush=True)
    print(f"WS-02b {args.mode} {len(tests)}/{len(tests)} PASS", flush=True)


if __name__ == "__main__":
    main()
