#!/usr/bin/env python3
"""WS-02d: malformed RFC 6455 frames, UTF-8, fragmentation and resource cleanup.

Standard library only. Never sends unbounded payloads and tests rejection over TCP.
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


def upgrade(port, path="/echo"):
    sock = connect(port)
    request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: Upgrade\r\nUpgrade: websocket\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               f"Sec-WebSocket-Key: {KEY}\r\n\r\n")
    try:
        sock.sendall(request.encode("ascii"))
        header = bytearray()
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(4096)
            assert chunk, "handshake EOF"
            header.extend(chunk)
            assert len(header) < 16384
        head, carry = bytes(header).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 101 "), head
        accept_values = [line.partition(b":")[2].strip()
                         for line in head.split(b"\r\n")[1:]
                         if line.partition(b":")[0].strip().lower() ==
                         b"sec-websocket-accept"]
        assert accept_values == [ACCEPT], head
        return sock, carry
    except BaseException:
        sock.close()
        raise


def frame(payload=b"", opcode=1, fin=True, mask=True, rsv=0,
          force_extended=None):
    assert 0 <= opcode <= 15
    assert 0 <= rsv <= 7
    length = len(payload)
    if force_extended == 16:
        encoded = b"\x7e" + length.to_bytes(2, "big")
    elif force_extended == 64:
        encoded = b"\x7f" + length.to_bytes(8, "big")
    elif length <= 125:
        encoded = bytes((length,))
    elif length <= 65535:
        encoded = b"\x7e" + length.to_bytes(2, "big")
    else:
        encoded = b"\x7f" + length.to_bytes(8, "big")
    first = (0x80 if fin else 0) | (rsv << 4) | opcode
    if not mask:
        return bytes((first,)) + encoded + payload
    return (bytes((first, encoded[0] | 0x80)) + encoded[1:] + MASK +
            bytes(value ^ MASK[i % 4] for i, value in enumerate(payload)))


def recv_frame(sock, carry=b""):
    hdr, carry = take(sock, 2, carry)
    assert hdr[0] & 0x80, "non-FIN server reply"
    assert not hdr[1] & 0x80, "masked server reply"
    length = hdr[1] & 0x7f
    if length == 126:
        raw, carry = take(sock, 2, carry)
        length = int.from_bytes(raw, "big")
    elif length == 127:
        raw, carry = take(sock, 8, carry)
        length = int.from_bytes(raw, "big")
    assert length <= 1024 * 1024, "oversize server response"
    body, carry = take(sock, length, carry)
    return hdr[0] & 0x0f, body, carry


def assert_eof(sock, carry=b""):
    assert not carry, f"unexpected bytes: {carry[:48]!r}"
    try:
        rest = sock.recv(4096)
    except ConnectionResetError:
        return
    assert rest == b"", f"expected EOF: {rest[:48]!r}"


def http_body(port, path):
    with connect(port) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            assert chunk
            data.extend(chunk)
            assert len(data) < 16384
        header, carry = bytes(data).split(b"\r\n\r\n", 1)
        assert header.startswith(b"HTTP/1.1 200 "), header
        lengths = [int(line.partition(b":")[2].strip())
                   for line in header.split(b"\r\n")[1:]
                   if line.partition(b":")[0].strip().lower() ==
                   b"content-length"]
        assert len(lengths) == 1, header
        result, carry = take(sock, lengths[0], carry)
        assert not carry
        return result


def stats(port):
    values = tuple(map(int, http_body(port, "/stats").split(b",")))
    assert len(values) == 3, values
    return values


def reject(port, wire):
    before = stats(port)
    sock, carry = upgrade(port)
    with sock:
        assert not carry, carry
        sock.sendall(wire)
        assert_eof(sock)
    after = stats(port)
    assert after == (before[0] + 1, before[1], before[2]), (before, after)


def exchange(port, frames, expected, close=True):
    sock, carry = upgrade(port)
    with sock:
        sock.sendall(b"".join(frames))
        for opcode, body in expected:
            got_opcode, got_data, carry = recv_frame(sock, carry)
            assert (got_opcode, got_data) == (opcode, body), \
                ((got_opcode, got_data[:48]), (opcode, body[:48]))
        if close:
            sock.sendall(frame(b"", opcode=8))
            got_opcode, got_data, carry = recv_frame(sock, carry)
            assert (got_opcode, got_data) == (8, b"")
            assert_eof(sock, carry)


def test_valid_text_binary(port):
    exchange(port, [frame(b"hello"), frame(b"\x00\xff", opcode=2)],
             [(1, b"hello"), (2, b"\x00\xff")])


def test_valid_fragmented_utf8(port):
    value = "日本語".encode("utf-8")
    pieces = [value[:1], value[1:5], value[5:]]
    exchange(port, [frame(pieces[0], fin=False),
                    frame(pieces[1], opcode=0, fin=False),
                    frame(pieces[2], opcode=0)], [(1, value)])


def test_control_between_fragments(port):
    exchange(port, [frame(b"hel", fin=False),
                    frame(b"p", opcode=9),
                    frame(b"ignored", opcode=10),
                    frame(b"lo", opcode=0)],
             [(10, b"p"), (1, b"hello")])


def test_binary_fragment_control(port):
    exchange(port, [frame(b"\xff", opcode=2, fin=False),
                    frame(b"check", opcode=9),
                    frame(b"\x80\x00", opcode=0)],
             [(10, b"check"), (2, b"\xff\x80\x00")])


def test_ping_pong_outside_fragments(port):
    exchange(port, [frame(b"ok", opcode=9), frame(b"hello")],
             [(10, b"ok"), (1, b"hello")])
    exchange(port, [frame(b"ok", opcode=10), frame(b"hello")],
             [(1, b"hello")])


def test_close_while_fragmented(port):
    sock, carry = upgrade(port)
    with sock:
        sock.sendall(frame(b"not complete", fin=False) +
                     frame(b"\x03\xe8ok", opcode=8))
        opcode, body, carry = recv_frame(sock, carry)
        assert (opcode, body) == (8, b"\x03\xe8ok")
        assert_eof(sock, carry)


def test_rsv_rejection(port):
    for rsv in (1, 2, 4, 7):
        reject(port, frame(b"x", rsv=rsv))


def test_reserved_opcodes(port):
    for opcode in (3, 4, 5, 6, 7, 11, 12, 13, 14, 15):
        reject(port, frame(b"", opcode=opcode))


def test_unmasked_client(port):
    reject(port, frame(b"not masked", mask=False))


def test_control_not_fin(port):
    for opcode in (8, 9, 10):
        reject(port, frame(b"x", opcode=opcode, fin=False))


def test_control_oversize(port):
    for opcode in (8, 9, 10):
        # Declare a 126-byte control frame without sending a payload.
        # The parser must reject immediately, without waiting for bytes.
        reject(port, bytes((0x80 | opcode, 0xfe)))


def test_orphan_continuation(port):
    reject(port, frame(b"orphan", opcode=0))


def test_nested_data_frame(port):
    reject(port, frame(b"first", fin=False) + frame(b"new", opcode=1))
    reject(port, frame(b"first", opcode=2, fin=False) +
           frame(b"other", opcode=2))


def test_invalid_close_body(port):
    for value in (b"\x03", b"\x03\xed", b"\x03\xee",
                  b"\x03\xe8\xff", b"\x03\xe8\xc0\x80",
                  b"\x13\x88", b"\x00\x00"):
        reject(port, frame(value, opcode=8))


def test_invalid_utf8_text(port):
    for value in (b"\xff", b"\xc0\x80", b"\xed\xa0\x80",
                  b"\xf4\x90\x80\x80", b"\xe3\x81"):
        reject(port, frame(value))
    reject(port, frame(b"\xe3", fin=False) + frame(b"x", opcode=0))


def test_valid_close_code_reason(port):
    payload = b"\x0b\xb8" + "切断".encode("utf-8")  # code 3000
    sock, carry = upgrade(port)
    with sock:
        sock.sendall(frame(payload, opcode=8))
        opcode, body, carry = recv_frame(sock, carry)
        assert (opcode, body) == (8, payload)
        assert_eof(sock, carry)


def fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def test_fd_cycles(port, pid):
    baseline = fd_count(pid)
    for _ in range(30):
        reject(port, frame(b"x", opcode=3))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and fd_count(pid) > baseline + 2:
        time.sleep(.02)
    assert fd_count(pid) <= baseline + 2, (baseline, fd_count(pid))


def test_http_alive(port):
    assert http_body(port, "/health") == b"alive"
    assert stats(port)[1] == 0, "unexpected server exception"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    tests = (test_valid_text_binary, test_valid_fragmented_utf8,
             test_control_between_fragments, test_binary_fragment_control,
             test_ping_pong_outside_fragments, test_close_while_fragmented,
             test_rsv_rejection, test_reserved_opcodes, test_unmasked_client,
             test_control_not_fin, test_control_oversize,
             test_orphan_continuation, test_nested_data_frame,
             test_invalid_close_body, test_invalid_utf8_text,
             test_valid_close_code_reason, test_fd_cycles, test_http_alive)
    for test in tests:
        start = time.monotonic()
        if test is test_fd_cycles:
            test(args.port, args.pid)
        else:
            test(args.port)
        print(f"PASS {args.mode}: {test.__name__} "
              f"({time.monotonic() - start:.3f}s)", flush=True)
    print(f"WS-02d {args.mode} {len(tests)}/{len(tests)} PASS", flush=True)


if __name__ == "__main__":
    main()
