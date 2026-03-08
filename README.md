# Merkle Tree Lab

A simple experiment demonstrating Certificate Transparency concepts using [Trillian](https://github.com/google/trillian): certificates as Merkle tree leaves, public append-only logs, inclusion proofs, and root signatures.

## Prerequisites

- Go ≥ 1.22 (Trillian requires 1.25+)
- Docker
- OpenSSL
- jq (for demo.sh)

## Setup

### 1. Start MySQL

```bash
docker compose up -d mysql
# Wait for MySQL to be ready (~10 seconds)
```

### 2. Build and run Trillian services

```bash
cd impl/trillian
go build ./cmd/trillian_log_server ./cmd/trillian_log_signer
```

In one terminal, start the log server:

```bash
./trillian_log_server \
  --mysql_uri="root:root@tcp(127.0.0.1:3306)/trillian" \
  --rpc_endpoint="localhost:8090"
```

In another terminal, start the signer:

```bash
./trillian_log_signer \
  --mysql_uri="root:root@tcp(127.0.0.1:3306)/trillian" \
  --rpc_endpoint="localhost:8090" \
  --force_master
```

### 3. Build lab tools

```bash
cd ../..
go build -o create_tree ./cmd/create_tree
go build -o submit_cert ./cmd/submit_cert
go build -o get_sth ./cmd/get_sth
go build -o get_proof ./cmd/get_proof
go build -o verify_proof ./cmd/verify_proof
```

## Quick Demo

```bash
./demo.sh
```

This will: create a tree, generate a certificate, submit it to the log, fetch the proof, create a merkle certificate bundle, and verify the inclusion proof.

## Manual Usage

```bash
# Create a transparency log tree
./create_tree

# Generate 100 test certificates
scripts/gen_cert.sh 100

# Submit certificates to the log
./submit_cert

# Get the signed tree head
./get_sth -output sth.json

# Get inclusion proof for a certificate
./get_proof -cert certs/cert-0.pem -output proof.json

# Verify the proof
./verify_proof -cert certs/cert-0.pem -proof proof.json -sth sth.json
```

## Output Files

- `tree_id.txt` — Created tree ID
- `leaf_index.txt` — Last submitted leaf index
- `sth.json` — Signed tree head (tree size, root hash, timestamp)
- `proof.json` — Inclusion proof (leaf hash, audit path)
- `merkle_cert.json` — Merkle certificate bundle (cert + proof + STH)

## Learning Outcomes

This experiment demonstrates:

- Certificates as Merkle tree leaves
- Public append-only logs
- Inclusion proofs
- Root signatures
- How systems like Certificate Transparency work internally
