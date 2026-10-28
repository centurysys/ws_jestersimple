#!/usr/bin/env bash
# WS-03c: independent namespace and package smoke check.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${1:-/tmp/ws03c-results}"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"

# A ZIP overlay alone does not delete the old module/package name.
for old in ws.nimble src/ws.nim src/ws/jester_extra.nim src/ws/jestersimple_extra.nim; do
  if [[ -e "$old" ]]; then
    echo "Legacy path remains: $old (remove it before testing)" >&2
    exit 2
  fi
done

command -v nim >/dev/null || { echo 'Missing Nim compiler' >&2; exit 2; }
if [[ -n "${JS_ROOT:-}" ]]; then
  test -f "$JS_ROOT/jestersimple.nim" || { echo 'Invalid JS_ROOT' >&2; exit 2; }
  flags=(--path:src --path:"$(realpath "$JS_ROOT")")
else
  flags=(--path:src)
fi
nim --version > "$OUT/nim-version.txt"
for mode in debug release; do
  opts=(--mm:orc --hints:off "${flags[@]}")
  [[ "$mode" != release ]] || opts+=(-d:release)
  if ! nim c "${opts[@]}" --out:"$OUT/ws03c_imports_$mode" \
      tests/packaging/ws03c_imports.nim > "$OUT/build-$mode.log" 2>&1; then
    tail -n 100 "$OUT/build-$mode.log" >&2
    exit 1
  fi
  "$OUT/ws03c_imports_$mode" > "$OUT/run-$mode.log"
  grep -q 'WS-03c module imports OK' "$OUT/run-$mode.log"
  echo "PASS $mode: package/module imports"
done
