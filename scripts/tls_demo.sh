#!/usr/bin/env bash
# Private-PQC-PKI TLS demo (section 2 of the workshop).
#
# Modes:
#   (default)  one-shot: start a quiet server, connect one client, shut down
#   server     leave a verbose TLS server running (Ctrl-C to stop)
#   client     connect a verbose TLS client (use a second terminal)
#
# Prerequisites: run `make pki ALG=mldsa65` first, with OpenSSL 3.5+ on PATH.
#
# Examples:
#   make tls-demo
#   ./scripts/tls_demo.sh server          # terminal 1
#   ./scripts/tls_demo.sh client          # terminal 2
#   ALG=mldsa44 ./scripts/tls_demo.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-oneshot}"
ALG="${ALG:-mldsa65}"
PKI_DIR="${PKI_DIR:-out/pki/$ALG}"
PORT="${PORT:-4443}"
HOST="${HOST:-127.0.0.1}"
OPENSSL_BIN="${OPENSSL:-openssl}"

usage() {
  cat <<EOF
Usage: $0 [oneshot|server|client]

  oneshot   (default) start server, run one client, exit
  server    run openssl s_server in the foreground with full verbosity
  client    run openssl s_client in the foreground with full verbosity

Environment: ALG, PKI_DIR, PORT, HOST, OPENSSL
EOF
}

require_pki() {
  if [[ ! -f "$PKI_DIR/leaf.crt" || ! -f "$PKI_DIR/leaf.key" ]]; then
    echo "Missing $PKI_DIR/leaf.crt — run: make pki ALG=$ALG" >&2
    exit 1
  fi
}

print_openssl() {
  local resolved
  resolved="$(command -v "$OPENSSL_BIN" || true)"
  if [[ -z "$resolved" ]]; then
    echo "OpenSSL binary not found: $OPENSSL_BIN" >&2
    exit 1
  fi
  echo "OpenSSL: $resolved"
  "$OPENSSL_BIN" version
  if [[ -n "${OPENSSL_MODULES:-}" ]]; then
    echo "OPENSSL_MODULES=$OPENSSL_MODULES"
  fi
}

server_cmd=(
  "$OPENSSL_BIN" s_server
  -accept "$PORT"
  -cert "$PKI_DIR/leaf.crt"
  -key "$PKI_DIR/leaf.key"
  -cert_chain "$PKI_DIR/int.crt"
  -CAfile "$PKI_DIR/root.crt"
  -tls1_3
)

client_cmd=(
  "$OPENSSL_BIN" s_client
  -connect "$HOST:$PORT"
  -CAfile "$PKI_DIR/root.crt"
  -tls1_3
  -servername leaf.example
)

case "$MODE" in
  -h|--help|help)
    usage
    exit 0
    ;;
  oneshot|server|client)
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac

require_pki
print_openssl
echo "Algorithm: $ALG  PKI: $PKI_DIR  endpoint: $HOST:$PORT"
echo

if [[ "$MODE" == "server" ]]; then
  echo "Starting verbose TLS 1.3 server (Ctrl-C to stop) ..."
  echo "In another terminal: ./scripts/tls_demo.sh client"
  echo
  # No -quiet: handshake / accept lines stay on the terminal.
  exec "${server_cmd[@]}"
fi

if [[ "$MODE" == "client" ]]; then
  echo "Connecting verbose TLS 1.3 client ..."
  echo "(press Enter, then Ctrl-D / Ctrl-C when finished)"
  echo
  # Full client transcript — do not filter or discard stderr.
  exec "${client_cmd[@]}"
fi

# --- oneshot mode ----------------------------------------------------------
SERVER_LOG="$(mktemp "${TMPDIR:-/tmp}/tls_demo_server.XXXXXX.log")"
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$SERVER_LOG"
}
trap cleanup EXIT

echo "Starting TLS 1.3 server on $HOST:$PORT with $ALG leaf ..."
"${server_cmd[@]}" -quiet >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Confirm the server stayed up. A wrong OpenSSL (e.g. system 3.0) dies when
# loading the PQ key; previously grep || true hid that and printed success.
sleep 0.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Server failed to start. OpenSSL output:" >&2
  cat "$SERVER_LOG" >&2
  exit 1
fi

echo "Connecting client ..."
CLIENT_OUT="$(mktemp "${TMPDIR:-/tmp}/tls_demo_client.XXXXXX.log")"
set +e
echo | "${client_cmd[@]}" >"$CLIENT_OUT" 2>&1
CLIENT_RC=$?
set -e

grep -E "Cipher is|Peer signature type|Verify return code|subject=|Verification|Protocol  :" \
  "$CLIENT_OUT" || true

if [[ $CLIENT_RC -ne 0 ]]; then
  echo >&2
  echo "Client failed (exit $CLIENT_RC). Full openssl s_client output:" >&2
  cat "$CLIENT_OUT" >&2
  if [[ -s "$SERVER_LOG" ]]; then
    echo >&2
    echo "Server log:" >&2
    cat "$SERVER_LOG" >&2
  fi
  rm -f "$CLIENT_OUT"
  exit "$CLIENT_RC"
fi

if ! grep -q "Verify return code: 0" "$CLIENT_OUT"; then
  echo >&2
  echo "TLS connected but certificate verification did not succeed." >&2
  echo "Full openssl s_client output:" >&2
  cat "$CLIENT_OUT" >&2
  rm -f "$CLIENT_OUT"
  exit 1
fi

rm -f "$CLIENT_OUT"
echo
echo "OK: client validated the chain; server signed the handshake with the PQ key."
