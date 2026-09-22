#!/usr/bin/env bash
# Start/stop the local tlog witness used by the WS6 demo.
#
# Usage: scripts/run_witness.sh {start|stop}
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN="${BIN:-bin/witness}"
WITNESS_DIR="${WITNESS_DIR:-out/witness}"
LISTEN="${WITNESS_LISTEN:-127.0.0.1:8100}"
PID_FILE="$WITNESS_DIR/witness.pid"
LOG_FILE="$WITNESS_DIR/witness.log"

start() {
  if [[ ! -x "$BIN" ]]; then
    echo "Witness binary missing; run scripts/setup_witness.sh first" >&2
    exit 1
  fi
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Witness already running (pid $(cat "$PID_FILE"))"
    return 0
  fi
  mkdir -p "$WITNESS_DIR"
  nohup "$BIN" serve \
    --listen "$LISTEN" \
    --signer-key "$WITNESS_DIR/witness.key" \
    --log-vkey "$WITNESS_DIR/log-vkey.txt" \
    >"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Witness failed to start:" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi
  echo "Witness listening on $LISTEN (pid $(cat "$PID_FILE"))"
}

stop() {
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "Stopped witness (pid $pid)"
  else
    pkill -x witness 2>/dev/null || true
    echo "No pid file; stopped any running witness"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 {start|stop}" >&2; exit 2 ;;
esac
