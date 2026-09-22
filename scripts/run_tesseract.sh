#!/usr/bin/env bash
# Build (if needed) and run the TesseraCT POSIX CT log locally.
#
# Usage: scripts/run_tesseract.sh {start|stop|restart}
#
# Environment:
#   BIN           path to the built binary      (default bin/tesseract-posix)
#   STORAGE_DIR   log storage directory         (default log)
#   ORIGIN        checkpoint origin             (default example.com/workshop)
#   HTTP_ADDR     submission endpoint           (default 127.0.0.1:6962)
#   ROOTS_PEM     accepted roots PEM            (default out/pki/mldsa65/root.crt)
#   LOG_KEY       ECDSA checkpoint signing key  (default out/log-key.pem)
#   ADDITIONAL_SIGNER  optional Ed25519 note signer for the log (witnessing)
#   WITNESS_POLICY     optional witness policy file (enables witnessing)
#   GOTOOLCHAIN   Go toolchain                  (default go1.27.0)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN="${BIN:-bin/tesseract-posix}"
STORAGE_DIR="${STORAGE_DIR:-log}"
ORIGIN="${ORIGIN:-example.com/workshop}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
ROOTS_PEM="${ROOTS_PEM:-out/pki/mldsa65/root.crt}"
LOG_KEY="${LOG_KEY:-out/log-key.pem}"
PID_FILE="$STORAGE_DIR/tesseract.pid"
LOG_FILE="$STORAGE_DIR/tesseract.log"

build_if_needed() {
  if [[ ! -x "$BIN" ]]; then
    echo "Building TesseraCT POSIX binary (Go ${GOTOOLCHAIN:-go1.27.0}) ..."
    (cd impl/tesseract && GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.0}" go build -o "../../$BIN" ./cmd/tesseract/posix)
  fi
}

ensure_log_key() {
  if [[ ! -f "$LOG_KEY" ]]; then
    echo "Generating ECDSA log signing key: $LOG_KEY"
    mkdir -p "$(dirname "$LOG_KEY")"
    openssl ecparam -name prime256v1 -genkey -noout -out "$LOG_KEY"
  fi
}

ensure_roots() {
  if [[ ! -f "$ROOTS_PEM" ]]; then
    echo "Roots not found ($ROOTS_PEM); generating the mldsa65 PKI ..."
    python3 -m lab.cli pki --algorithm mldsa65
  fi
}

start() {
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "TesseraCT already running (pid $(cat "$PID_FILE"))"
    return 0
  fi
  build_if_needed
  ensure_log_key
  ensure_roots
  mkdir -p "$STORAGE_DIR"

  extra_args=()
  if [[ -n "${ADDITIONAL_SIGNER:-}" ]]; then
    extra_args+=(--additional_signer="$ADDITIONAL_SIGNER")
  fi
  if [[ -n "${WITNESS_POLICY:-}" ]]; then
    extra_args+=(--witness_policy_file="$WITNESS_POLICY")
  fi

  export GOMEMLIMIT="${GOMEMLIMIT:-2GiB}"
  nohup "$BIN" \
    --http_endpoint="$HTTP_ADDR" \
    --storage_dir="$STORAGE_DIR" \
    --origin="$ORIGIN" \
    --private_key="$LOG_KEY" \
    --roots_pem_file="$ROOTS_PEM" \
    --checkpoint_interval="${CHECKPOINT_INTERVAL:-1s}" \
    --enable_publication_awaiter=false \
    --slog_level="${SLOG_LEVEL:-1}" \
    "${extra_args[@]}" \
    >"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"

  for _ in $(seq 1 40); do
    [[ -f "$STORAGE_DIR/checkpoint" ]] && break
    sleep 0.25
  done

  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "TesseraCT failed to start; last log lines:" >&2
    tail -20 "$LOG_FILE" >&2 || true
    exit 1
  fi
  echo "TesseraCT running on http://$HTTP_ADDR"
  echo "  origin : $ORIGIN"
  echo "  storage: $STORAGE_DIR"
  echo "  pid    : $(cat "$PID_FILE")"
}

stop() {
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true
    sleep 0.5
    rm -f "$PID_FILE"
    echo "Stopped TesseraCT (pid $pid)"
  else
    pkill -x tesseract-posix 2>/dev/null || true
    echo "No pid file; stopped any running tesseract-posix process"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  *) echo "usage: $0 {start|stop|restart}" >&2; exit 2 ;;
esac
