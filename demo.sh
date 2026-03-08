#!/bin/bash
# Merkle Tree Lab - Full demo flow
# Prerequisites: Docker, MySQL running (docker compose up -d mysql),
#               Trillian log server and signer running

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Merkle Tree Lab Demo ==="

# Check Trillian services (optional - will fail later if not running)
echo ""
echo "Note: Ensure Trillian log server and signer are running on localhost:8090"
echo "  cd impl/trillian && ./trillian_log_server --mysql_uri='root:root@tcp(127.0.0.1:3306)/trillian' --rpc_endpoint='localhost:8090'"
echo "  ./trillian_log_signer --mysql_uri='root:root@tcp(127.0.0.1:3306)/trillian' --rpc_endpoint='localhost:8090' --force_master"

# Build our tools
echo ""
echo "Building tools..."
go build -o create_tree ./cmd/create_tree
go build -o submit_cert ./cmd/submit_cert
go build -o get_sth ./cmd/get_sth
go build -o get_proof ./cmd/get_proof
go build -o verify_proof ./cmd/verify_proof

# Create tree if needed
if [ ! -f tree_id.txt ]; then
  echo ""
  echo "Creating transparency log tree..."
  ./create_tree
else
  echo ""
  echo "Using existing tree (tree_id.txt)"
fi

# Generate a single certificate for demo
echo ""
echo "Generating certificate..."
mkdir -p certs
scripts/gen_cert.sh 1

# Submit to log
echo ""
echo "Submitting to log..."
./submit_cert

# Fetch STH
echo ""
echo "Fetching signed tree head..."
./get_sth -output sth.json

# Fetch inclusion proof (for cert-0.pem, leaf index 0)
echo ""
echo "Fetching inclusion proof..."
./get_proof -cert certs/cert-0.pem -output proof.json

# Create merkle certificate bundle
echo ""
echo "Creating merkle certificate bundle..."
jq -n \
  --rawfile cert certs/cert-0.pem \
  --slurpfile proof proof.json \
  --slurpfile sth sth.json \
  '{certificate: ($cert | @base64), leaf_index: ($proof[0].leaf_index // 0), proof: $proof[0].audit_path, signed_tree_head: $sth[0]}' \
  > merkle_cert.json
echo "Wrote merkle_cert.json"

# Verify proof
echo ""
echo "Verifying inclusion..."
./verify_proof -cert certs/cert-0.pem -proof proof.json -sth sth.json

echo ""
echo "SUCCESS"
