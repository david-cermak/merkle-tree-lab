#!/usr/bin/env bash
# Build (if needed) and run the TesseraCT POSIX CT log locally.
#
# Usage: scripts/run_tesseract.sh {start|stop|restart|reset}
#
# Environment:
#   BIN           path to the built binary      (default bin/tesseract-posix)
#   STORAGE_DIR   log storage directory         (default log)
#   ORIGIN        checkpoint origin             (default example.com/workshop)
#   HTTP_ADDR     submission endpoint           (default 127.0.0.1:6962)
#   ROOTS_PEM     accepted roots PEM            (default out/pki/workshop-roots.pem)
#   LOG_KEY       ECDSA checkpoint signing key  (default out/log-key.pem)
#   GOTOOLCHAIN   Go toolchain                  (default go1.27.0)
#
# reset = stop, wipe STORAGE_DIR, start — use when restarting a workshop so the
# log is empty again. A CT log is append-only; there is no "delete entry" API.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN="${BIN:-bin/tesseract-posix}"
STORAGE_DIR="${STORAGE_DIR:-log}"
ORIGIN="${ORIGIN:-example.com/workshop}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
ROOTS_PEM="${ROOTS_PEM:-out/pki/workshop-roots.pem}"
LOG_KEY="${LOG_KEY:-out/log-key.pem}"
PID_FILE="$STORAGE_DIR/tesseract.pid"
LOG_FILE="$STORAGE_DIR/tesseract.log"
PYTHON="${PYTHON:-$(test -x .venv/bin/python && echo .venv/bin/python || echo python3)}"

# The submission prefix of an origin is $HOST/$PATH_PREFIX, and per the
# static-ct-api the origin line must be exactly that prefix. TesseraCT only
# learns the path half of it from its own configuration, so the path half of
# ORIGIN has to be handed back to it as --path_prefix. "example.com/workshop"
# becomes "--path_prefix=/workshop", so that a submission is received at
# /workshop/ct/v1/add-chain and the endpoint the server reconstructs,
# $HOST$PATH, starts with the origin it was told about.
ORIGIN_PATH="${ORIGIN#*/}"
if [[ "$ORIGIN_PATH" == "$ORIGIN" ]]; then
  PATH_PREFIX=""
else
  PATH_PREFIX="/${ORIGIN_PATH#/}"
  PATH_PREFIX="${PATH_PREFIX%/}"
fi

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
  # Default workshop roots accept both a classical (ECDSA) and a PQC (ML-DSA)
  # chain so exercise 03 can submit classical first, then compare PQC size,
  # without restarting TesseraCT with a different --roots_pem_file.
  if [[ "$ROOTS_PEM" == "out/pki/workshop-roots.pem" ]]; then
    local need_rebuild=0
    [[ -f "$ROOTS_PEM" ]] || need_rebuild=1
    if [[ ! -f out/pki/ecdsa-p256/root.crt ]]; then
      echo "Generating ecdsa-p256 PKI for workshop roots ..."
      "$PYTHON" -m lab.cli pki --algorithm ecdsa-p256
      need_rebuild=1
    fi
    if [[ ! -f out/pki/mldsa65/root.crt ]]; then
      echo "Generating mldsa65 PKI for workshop roots ..."
      "$PYTHON" -m lab.cli pki --algorithm mldsa65
      need_rebuild=1
    fi
    if [[ "$need_rebuild" -eq 1 ]] \
      || [[ out/pki/ecdsa-p256/root.crt -nt "$ROOTS_PEM" ]] \
      || [[ out/pki/mldsa65/root.crt -nt "$ROOTS_PEM" ]]; then
      mkdir -p "$(dirname "$ROOTS_PEM")"
      cat out/pki/ecdsa-p256/root.crt out/pki/mldsa65/root.crt >"$ROOTS_PEM"
      echo "Wrote workshop roots: $ROOTS_PEM (ecdsa-p256 + mldsa65)"
    fi
    return 0
  fi
  if [[ ! -f "$ROOTS_PEM" ]]; then
    echo "Roots not found ($ROOTS_PEM); generating the mldsa65 PKI ..."
    "$PYTHON" -m lab.cli pki --algorithm mldsa65
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

  export GOMEMLIMIT="${GOMEMLIMIT:-2GiB}"
  prefix_args=()
  [[ -n "$PATH_PREFIX" ]] && prefix_args=(--path_prefix="$PATH_PREFIX")
  nohup "$BIN" \
    --http_endpoint="$HTTP_ADDR" \
    --storage_dir="$STORAGE_DIR" \
    --origin="$ORIGIN" \
    "${prefix_args[@]}" \
    --private_key="$LOG_KEY" \
    --roots_pem_file="$ROOTS_PEM" \
    --checkpoint_interval="${CHECKPOINT_INTERVAL:-1s}" \
    --enable_publication_awaiter=false \
    --slog_level="${SLOG_LEVEL:-1}" \
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
  echo "  prefix : ${PATH_PREFIX:-<none>}  (submit to http://$HTTP_ADDR${PATH_PREFIX}/ct/v1/...)"
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

reset() {
  # Wipe every persisted object (checkpoint, tiles, antispam state, issuers).
  # There is no Static CT API to delete entries — the only clean slate is a
  # fresh storage directory.
  stop
  if [[ -d "$STORAGE_DIR" ]]; then
    echo "Wiping log storage: $STORAGE_DIR"
    rm -rf "$STORAGE_DIR"
  fi
  start
  if [[ -f "$STORAGE_DIR/checkpoint" ]]; then
    size="$(sed -n '2p' "$STORAGE_DIR/checkpoint")"
    echo "Log reset complete (tree size: ${size:-0})"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  reset) reset ;;
  *) echo "usage: $0 {start|stop|restart|reset}" >&2; exit 2 ;;
esac
