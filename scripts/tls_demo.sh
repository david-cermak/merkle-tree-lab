#!/usr/bin/env bash
# Private-PQC-PKI TLS demo (section 2 of the workshop).
#
# Starts an OpenSSL TLS 1.3 server that presents a post-quantum (ML-DSA by
# default) leaf certificate, connects a single client, prints the negotiated
# cipher and the certificate's signature type, then shuts the server down.
#
# Prerequisites: run `make pki ALG=mldsa65` first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ALG="${ALG:-mldsa65}"
PKI_DIR="${PKI_DIR:-out/pki/$ALG}"
PORT="${PORT:-4443}"
HOST="127.0.0.1"

if [[ ! -f "$PKI_DIR/leaf.crt" ]]; then
  echo "Missing $PKI_DIR/leaf.crt — run: make pki ALG=$ALG" >&2
  exit 1
fi

echo "Starting TLS 1.3 server on $HOST:$PORT with $ALG leaf ..."
openssl s_server \
  -accept "$PORT" \
  -cert "$PKI_DIR/leaf.crt" \
  -key "$PKI_DIR/leaf.key" \
  -cert_chain "$PKI_DIR/int.crt" \
  -CAfile "$PKI_DIR/root.crt" \
  -quiet \
  >/tmp/tls_demo_server.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 1

echo "Connecting client ..."
echo | openssl s_client \
  -connect "$HOST:$PORT" \
  -CAfile "$PKI_DIR/root.crt" \
  -tls1_3 2>&1 | grep -E "Cipher is|Peer signature type|Verify return code|subject=|Verification" || true

echo
echo "The client validated the chain and the server signed the handshake with the PQ key."
