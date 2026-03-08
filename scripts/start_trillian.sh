#!/bin/bash
# Start Trillian log server and signer.
# Run from project root. MySQL must be running (docker compose up -d mysql).

set -e

cd "$(dirname "$0")/.."
TRILLIAN_DIR="impl/trillian"

if [ ! -d "$TRILLIAN_DIR" ]; then
  echo "Trillian not found at $TRILLIAN_DIR"
  exit 1
fi

cd "$TRILLIAN_DIR"

# Build if needed
if [ ! -f ./trillian_log_server ]; then
  echo "Building Trillian..."
  go build -o trillian_log_server ./cmd/trillian_log_server
  go build -o trillian_log_signer ./cmd/trillian_log_signer
fi

MYSQL_URI="${MYSQL_URI:-root:root@tcp(127.0.0.1:3306)/trillian}"

echo "Starting Trillian log server (MySQL: $MYSQL_URI)..."
./trillian_log_server \
  --mysql_uri="$MYSQL_URI" \
  --rpc_endpoint="localhost:8090" \
  --http_endpoint="localhost:8091" &

SERVER_PID=$!
sleep 2

echo "Starting Trillian log signer..."
./trillian_log_signer \
  --mysql_uri="$MYSQL_URI" \
  --rpc_endpoint="localhost:8090" \
  --force_master &

SIGNER_PID=$!

echo ""
echo "Trillian running. Log server PID: $SERVER_PID, Signer PID: $SIGNER_PID"
echo "Press Ctrl+C to stop both."
trap "kill $SERVER_PID $SIGNER_PID 2>/dev/null; exit" INT TERM
wait
