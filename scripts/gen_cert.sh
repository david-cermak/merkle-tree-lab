#!/bin/bash
# Generate N self-signed test certificates using OpenSSL.
# Certificates are stored in certs/ as cert-N.pem and key-N.pem.

set -e

N=${1:-100}
CERT_DIR="${CERT_DIR:-certs}"

mkdir -p "$CERT_DIR"

for i in $(seq 0 $((N - 1))); do
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key-$i.pem" \
    -out "$CERT_DIR/cert-$i.pem" \
    -days 365 \
    -nodes \
    -subj "/CN=test.example-$i" \
    -batch 2>/dev/null
done

echo "Generated $N certificates in $CERT_DIR/"
