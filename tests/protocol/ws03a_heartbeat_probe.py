#!/usr/bin/env python3
"""WS-03a: wire-level control frames, read deadlines and heartbeat lifecycle.

No external dependencies. Uses masked client frames and bounded I/O.
"""
import argparse
import os
import socket
import time

HOST = "127.0.0.1"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MASK = b"\x19\x23\x31\x42"


def connect(port):
    sock = socket.create_connection((HOST, port), timeout=2)
    sock.settimeout(2)
    return sock


def take(sock, count, carry=b""):
    buf = bytearray(carry)
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        assert chunk, f"early EOF: {len(buf)}/{count}"
        buf.extend(chunk)
    return bytes(buf[:count]), bytes(buf[count:])


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
            assert chunk, "handshake EOF"
            data.extend(chunk)
            assert len(data) < 16384
        head, carry = bytes(data).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 101 "), head
        values = [line.partition(b":")[2].strip()
                  for line in head.split(b"\r\n")[1:]
                  if line.partition(b":")[0].strip().lower() ==
                  b"sec-websocket-accept"]
        assert values == [ACCEPT], head
        return sock, carry
    except BaseException:
        sock.close()
        raise


def frame(body=b"", opcode=1):
    assert len(body) <= 65535
    if len(body) <= 125:
        head = bytes((len(body) | 0x80,))
    else:
        head = b"\xfe" + len(body).to_bytes(2, "big")
    return (bytes((0x80 | opcode,)) + head + MASK +
            bytes(b ^ MASK[i % 4] for i, b in enumerate(body)))


def recv_frame(sock, carry=b""):
    header, carry = take(sock, 2, carry)
    assert header[0] & 0x80, "server sent non-FIN control/data frame"
    assert not header[1] & 0x80, "server frame must not be masked"
    length = header[1] & 0x7f
    if length == 126:
        raw, carry = take(sock, 2, carry)
        length = int.from_bytes(raw, "big")
    elif length == 127:
        raw, carry = take(sock, 8, carry)
        length = int.from_bytes(raw, "big")
    assert length <= 1 << 20, "server response too large"
    body, carry = take(sock, length, carry)
    return header[0] & 15, body, carry


def end_close(sock, carry=b""):
    sock.sendall(frame(b"", 8))
    opcode, data, carry = recv_frame(sock, carry)
    assert (opcode, data) == (8, b""), (opcode, data)
    assert_eof(sock, carry)


def assert_eof(sock, carry=b""):
    assert carry == b"", f"unexpected trailing data: {carry[:48]!r}"
    try:
        data = sock.recv(4096)
    except ConnectionResetError:
        return
    assert data == b"", f"expected EOF, got {data[:48]!r}"


def http_body(port, path):
    with connect(port) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        data = bytearray()
        while b"\r\n\r\n" not in data:
            part = sock.recv(4096)
            assert part
            data.extend(part)
        head, carry = bytes(data).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200 "), head
        lengths = [int(line.partition(b":")[2].strip())
                   for line in head.split(b"\r\n")[1:]
                   if line.partition(b":")[0].strip().lower() ==
                   b"content-length"]
        assert len(lengths) == 1, head
        body, remain = take(sock, lengths[0], carry)
        assert not remain
        return body


def stats(port):
    data = tuple(map(int, http_body(port, "/stats").split(b",")))
    assert len(data) == 3
    return data


def await_stat(port, index, previous):
    for _ in range(30):
        current = stats(port)
        if current[index] > previous[index]:
            assert current[index] == previous[index] + 1
            assert current[2] == previous[2], (previous, current)
            return
        time.sleep(.02)
    raise AssertionError(f"stat {index} unchanged from {previous}: {stats(port)}")


def test_text_controls(port):
    sock, carry = upgrade(port, "/text")
    with sock:
        sock.sendall(frame(b"A", 9) + frame(b"unsolicited", 10) +
                     frame(b"B", 9) + frame(b"hello", 1))
        for value in (b"A", b"B"):
            opcode, data, carry = recv_frame(sock, carry)
            assert (opcode, data) == (10, value), (opcode, data)
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (1, b"hello")
        end_close(sock, carry)


def test_binary_controls(port):
    sock, carry = upgrade(port, "/binary")
    with sock:
        sock.sendall(frame(b"p", 9) + frame(b"unused", 10) +
                     frame(b"\xff\x00\x80", 2))
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (10, b"p")
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (2, b"\xff\x00\x80")
        end_close(sock, carry)


def test_raw_packet_compat(port):
    sock, carry = upgrade(port, "/raw")
    with sock:
        sock.sendall(frame(b"raw", 9))
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (1, b"raw-ok")
        end_close(sock, carry)


def test_no_default_timeout(port):
    sock, carry = upgrade(port, "/default-idle")
    with sock:
        time.sleep(.31)
        sock.sendall(frame(b"no-expiry"))
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (1, b"no-expiry")
        end_close(sock, carry)


def test_read_idle(port):
    before = stats(port)
    sock, carry = upgrade(port, "/read-idle")
    with sock:
        assert not carry
        start = time.monotonic()
        assert_eof(sock)
        elapsed = time.monotonic() - start
        assert .11 <= elapsed < 1.25, elapsed
    await_stat(port, 0, before)


def test_read_partial(port):
    before = stats(port)
    sock, carry = upgrade(port, "/read-partial")
    with sock:
        wire = frame(b"partial")
        sock.sendall(wire[:7])
        assert_eof(sock, carry)
    await_stat(port, 0, before)


def test_heartbeat_ack(port):
    # Repeated immediate Pong replies catch races between sending a Ping and
    # marking its response as pending in the server's async loop.
    for _ in range(4):
        sock, carry = upgrade(port, "/heart-ok")
        with sock:
            count = 0
            while count < 3:
                opcode, data, carry = recv_frame(sock, carry)
                assert opcode == 9, (opcode, data)
                sock.sendall(frame(data, 10))
                count += 1
            sock.sendall(frame(b"live"))
            while True:
                opcode, data, carry = recv_frame(sock, carry)
                if opcode == 9:
                    sock.sendall(frame(data, 10))
                else:
                    assert (opcode, data) == (1, b"live")
                    break
            end_close(sock, carry)


def test_heartbeat_timeout(port):
    before = stats(port)
    sock, carry = upgrade(port, "/heart-timeout")
    with sock:
        opcode, data, carry = recv_frame(sock, carry)
        assert opcode == 9
        assert_eof(sock, carry)
    await_stat(port, 1, before)


def test_mismatched_pong(port):
    before = stats(port)
    sock, carry = upgrade(port, "/heart-wrong-pong")
    with sock:
        opcode, data, carry = recv_frame(sock, carry)
        assert opcode == 9
        sock.sendall(frame(b"wrong-pong", 10))
        assert_eof(sock, carry)
    await_stat(port, 1, before)


def watch_pings_until_marker(sock, carry, marker):
    ping_count = 0
    while True:
        opcode, data, carry = recv_frame(sock, carry)
        if opcode == 9:
            ping_count += 1
        else:
            assert (opcode, data) == (1, marker), (opcode, data)
            return carry, ping_count


def test_stop_pings(port):
    sock, carry = upgrade(port, "/stop")
    with sock:
        carry, count = watch_pings_until_marker(sock, carry, b"stopped")
        assert count >= 1, count
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (8, b""), (opcode, data)
        sock.sendall(frame(b"", 8))
        assert_eof(sock, carry)


def test_replace_pings(port):
    sock, carry = upgrade(port, "/replace")
    with sock:
        carry, count = watch_pings_until_marker(sock, carry, b"replaced")
        assert count >= 1
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (8, b""), (opcode, data)
        sock.sendall(frame(b"", 8))
        assert_eof(sock, carry)


def test_invalid_options(port):
    sock, carry = upgrade(port, "/config")
    with sock:
        opcode, data, carry = recv_frame(sock, carry)
        assert (opcode, data) == (1, b"7"), (opcode, data)
        end_close(sock, carry)


def test_fd_cycles(port, pid):
    before_stats = stats(port)
    before = len(os.listdir(f"/proc/{pid}/fd"))
    for _ in range(25):
        sock, carry = upgrade(port, "/text")
        with sock:
            sock.sendall(frame(b"hello"))
            opcode, data, carry = recv_frame(sock, carry)
            assert (opcode, data) == (1, b"hello")
            end_close(sock, carry)
    # Timed-out socket readers may be unblocked by a close callback. Allow
    # short async cleanup but do not permit monotonically growing FDs.
    time.sleep(.15)
    after = len(os.listdir(f"/proc/{pid}/fd"))
    assert after <= before + 3, (before, after)
    assert stats(port) == before_stats
    assert http_body(port, "/health") == b"alive"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = [test_text_controls, test_binary_controls,
             test_raw_packet_compat, test_no_default_timeout, test_read_idle,
             test_read_partial, test_heartbeat_ack, test_heartbeat_timeout,
             test_mismatched_pong, test_stop_pings, test_replace_pings,
             test_invalid_options]
    for test in tests:
        start = time.monotonic()
        test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - start:.3f}s)", flush=True)
    start = time.monotonic()
    test_fd_cycles(args.port, args.pid)
    print(f"PASS {args.mode}: test_fd_cycles "
          f"({time.monotonic() - start:.3f}s)", flush=True)
    print(f"WS-03a {args.mode} 13/13 PASS", flush=True)


if __name__ == "__main__":
    main()
