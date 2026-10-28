#!/usr/bin/env bash
# WS-01: run debug/release loopback tests without modifying either repository.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${1:-/tmp/ws01-results}"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in nim python3; do
  command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 2; }
done
nim --version > "$OUT/nim-version.txt"
python3 -m py_compile tests/jestersimple/ws01_probe.py

# Set JS_ROOT to the unpacked JS-12 Jester Simple repository root.
JS_ROOT="${JS_ROOT:?Set JS_ROOT to the JS-12 Jester Simple root directory}"
JS_ROOT="$(realpath "$JS_ROOT")"
test -f "$JS_ROOT/jestersimple.nim"

for mode in debug release; do
  flags=(--mm:orc --hints:off --path:src --path:"$JS_ROOT")
  [[ "$mode" != release ]] || flags+=(-d:release)
  binary="$OUT/ws01_server_$mode"
  if ! nim c "${flags[@]}" --out:"$binary" \
      tests/jestersimple/ws01_server.nim > "$OUT/build-$mode.log" 2>&1; then
    tail -n 100 "$OUT/build-$mode.log" >&2
    exit 1
  fi

  port="$(python3 - <<'PYPORT'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PYPORT
)"
  WS01_PORT="$port" "$binary" > "$OUT/server-$mode.log" 2>&1 &
  SERVER_PID="$!"
  if ! python3 - "$SERVER_PID" "$port" <<'PYREADY'; then
import os, socket, sys, time
pid, port = int(sys.argv[1]), int(sys.argv[2])
for _ in range(70):
    try:
        os.kill(pid, 0)
        with socket.create_connection(('127.0.0.1', port), timeout=.2):
            sys.exit(0)
    except OSError:
        time.sleep(.1)
raise SystemExit('WS-01 test server did not become ready')
PYREADY
    tail -n 100 "$OUT/server-$mode.log" >&2
    exit 1
  fi
  sleep 0.1
  if ! python3 tests/jestersimple/ws01_probe.py \
      --port "$port" --pid "$SERVER_PID" --mode "$mode" \
      > "$OUT/probe-$mode.log" 2>&1; then
    cat "$OUT/probe-$mode.log" >&2
    tail -n 100 "$OUT/server-$mode.log" >&2
    exit 1
  fi
  cat "$OUT/probe-$mode.log"
  cleanup
done
