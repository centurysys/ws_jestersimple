#!/usr/bin/env python3
"""WS-02c: RFC 6455 length parsing, frame/message caps and FD regression.

Uses only Python's standard library. Deliberately declares huge payload lengths
without transmitting payload bytes: rejection must precede buffering/recv.
"""
import argparse
import os
import socket
import time

HOST = "127.0.0.1"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MASK = b"\x12\x34\x56\x78"
DEFAULT_FRAME = 1024 * 1024


def connect(port):
    sock = socket.create_connection((HOST, port), timeout=2.0)
    sock.settimeout(1.5)
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
    request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: Upgrade\r\nUpgrade: websocket\r\n"
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


def frame(payload, opcode=1, fin=True):
    length = len(payload)
    if length <= 125:
        ext = bytes([0x80 | length])
    elif length <= 65535:
        ext = b"\xfe" + length.to_bytes(2, "big")
    else:
        ext = b"\xff" + length.to_bytes(8, "big")
    return (bytes([(0x80 if fin else 0) | opcode]) + ext + MASK +
            bytes(value ^ MASK[i % 4] for i, value in enumerate(payload)))


def declared_length(length, bits):
    assert bits in (16, 64)
    return bytes([0x81, 0xfe if bits == 16 else 0xff]) + \
        length.to_bytes(bits // 8, "big")


def recv_frame(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    assert header[0] & 0x80, "non-FIN response"
    assert not (header[1] & 0x80), "server masked response"
    length = header[1] & 0x7f
    if length == 126:
        raw, carry = take(sock, 2, carry)
        length = int.from_bytes(raw, "big")
    elif length == 127:
        raw, carry = take(sock, 8, carry)
        length = int.from_bytes(raw, "big")
    payload, carry = take(sock, length, carry)
    return header[0] & 0x0f, payload, carry


def assert_eof(sock, carry=b""):
    assert not carry, f"unexpected data after frame: {carry[:32]!r}"
    try:
        data = sock.recv(4096)
    except ConnectionResetError:
        return
    assert data == b"", f"expected EOF, got {data[:32]!r}"


def close_cleanly(sock, carry=b""):
    sock.sendall(frame(b"", opcode=8))
    kind, payload, carry = recv_frame(sock, carry)
    assert (kind, payload) == (8, b""), (kind, payload)
    assert_eof(sock, carry)


def http_body(port, path):
    with connect(port) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            assert chunk, "EOF during HTTP response"
            data.extend(chunk)
            assert len(data) < 16384
        header, carry = bytes(data).split(b"\r\n\r\n", 1)
        assert header.startswith(b"HTTP/1.1 200 "), header
        lengths = [int(line.partition(b":")[2].strip())
                   for line in header.split(b"\r\n")[1:]
                   if line.partition(b":")[0].strip().lower() ==
                   b"content-length"]
        assert len(lengths) == 1, header
        body, leftover = take(sock, lengths[0], carry)
        assert not leftover, leftover
        return body


def stats(port):
    values = tuple(map(int, http_body(port, "/stats").split(b",")))
    assert len(values) == 5, values
    return values


def expect_rejection(port, path, wire, counter):
    before = stats(port)
    sock, carry = upgrade(port, path)
    with sock:
        assert carry == b"", carry
        sock.sendall(wire)
        assert_eof(sock)
    after = stats(port)
    expected = list(before)
    expected[counter] += 1
    assert after == tuple(expected), (counter, before, after)


def echo(port, path, payload, fragments=None):
    sock, carry = upgrade(port, path)
    with sock:
        if fragments is None:
            sock.sendall(frame(payload))
        else:
            sock.sendall(b"".join(frame(part, opcode=1 if i == 0 else 0,
                                       fin=i == len(fragments) - 1)
                                  for i, part in enumerate(fragments)))
        opcode, response, carry = recv_frame(sock, carry)
        assert (opcode, response) == (1, payload), (opcode, len(response))
        close_cleanly(sock, carry)


def test_7_16_64_boundaries(port):
    for size in (0, 125, 126, 65535, 65536):
        echo(port, "/echo", bytes(range(256)) * (size // 256) +
             bytes(range(size % 256)))


def test_default_frame_limit(port):
    expect_rejection(port, "/echo",
                     declared_length(DEFAULT_FRAME + 1, 64), 0)


def test_full_64bit_high_words(port):
    # These were silently truncated to 0/1 by the original implementation.
    for length in (1 << 32, (1 << 32) + 1, (1 << 63) - 1):
        expect_rejection(port, "/echo", declared_length(length, 64), 0)


def test_64bit_high_bit(port):
    expect_rejection(port, "/echo", declared_length(1 << 63, 64), 2)


def test_nonminimal_lengths(port):
    expect_rejection(port, "/echo", declared_length(125, 16), 2)
    expect_rejection(port, "/echo", declared_length(65535, 64), 2)


def test_custom_frame_limit(port):
    echo(port, "/bounded", b"X" * 1024)
    expect_rejection(port, "/bounded", declared_length(1025, 16), 0)


def test_fragmented_message_exact_limit(port):
    pieces = [b"A" * 1024, b"B" * 1024]
    echo(port, "/bounded", b"".join(pieces), pieces)


def test_fragmented_message_over_limit(port):
    chunks = [frame(b"A" * 1024, fin=False),
              frame(b"B" * 1024, opcode=0, fin=False),
              frame(b"C", opcode=0, fin=True)]
    expect_rejection(port, "/bounded", b"".join(chunks), 1)


def test_message_limit_single_frame(port):
    # With a 1 KiB frame cap this is a frame error, not a message error.
    expect_rejection(port, "/bounded", declared_length(2049, 16), 0)


def test_http_alive(port):
    assert http_body(port, "/health") == b"alive"
    assert stats(port)[3] == 0, "unexpected server-side exceptions"


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def rss_kib(pid):
    with open(f"/proc/{pid}/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise AssertionError("missing VmRSS")


def test_resource_cycles(port, pid):
    before_fds = fd_count(pid)
    before_rss = rss_kib(pid)
    for _ in range(30):
        expect_rejection(port, "/echo",
                         declared_length((1 << 32) + 1, 64), 0)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and fd_count(pid) > before_fds + 2:
        time.sleep(0.02)
    after_fds = fd_count(pid)
    after_rss = rss_kib(pid)
    assert after_fds <= before_fds + 2, (before_fds, after_fds)
    assert after_rss - before_rss < 16 * 1024, (before_rss, after_rss)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_7_16_64_boundaries, test_default_frame_limit,
             test_full_64bit_high_words, test_64bit_high_bit,
             test_nonminimal_lengths, test_custom_frame_limit,
             test_fragmented_message_exact_limit,
             test_fragmented_message_over_limit,
             test_message_limit_single_frame, test_http_alive,
             test_resource_cycles)
    for test in tests:
        start = time.monotonic()
        if test is test_resource_cycles:
            test(args.port, args.pid)
        else:
            test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - start:.3f}s)", flush=True)
    print(f"WS-02c {args.mode} {len(tests)}/{len(tests)} PASS", flush=True)


if __name__ == "__main__":
    main()
