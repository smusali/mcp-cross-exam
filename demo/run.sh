#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pause() {
  if [[ "${DEMO_PAUSE:-}" == "1" ]]; then
    sleep "$1"
  fi
}

if [[ -n "${DEMO_PORT:-}" ]]; then
  port="${DEMO_PORT}"
else
  port="$(
    uv run python -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
  )"
fi

out="${DEMO_OUT:-$(mktemp -d)}"
mkdir -p "$out"

fixture_pid=""
cleanup() {
  status="$?"
  if [[ -n "${fixture_pid}" ]]; then
    kill "${fixture_pid}" 2>/dev/null || true
    wait "${fixture_pid}" 2>/dev/null || true
  fi
  exit "${status}"
}
trap cleanup EXIT

uv run mcp-cross-exam fixture serve \
  --http "127.0.0.1:${port}" \
  --era 2025-11-25 \
  --defects "session.expired-empty-success,schema.undeclared-required-arg" &
fixture_pid="$!"

uv run python -c '
import socket
import sys
import time

port = int(sys.argv[1])
for _ in range(50):
    try:
        with socket.create_connection(("127.0.0.1", port), 0.2):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
sys.stderr.write("fixture did not start\n")
raise SystemExit(1)
' "$port"

printf 'fixture http://127.0.0.1:%s/mcp\n' "$port"
pause 5

set +e
uv run mcp-cross-exam --seed 7 --out-dir "$out" "http://127.0.0.1:${port}/mcp"
code="$?"
set -e

pause 15

if [[ "${DEMO_PAUSE:-}" == "1" ]]; then
  html="${out}/report.html"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    open "$html" || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$html" || true
  fi
  pause 25
fi

exit "$code"
