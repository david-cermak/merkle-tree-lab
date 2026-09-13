#!/usr/bin/env bash
# WS6 demo: run a local witness, make TesseraCT cosign its checkpoints, and
# verify both the log signature and the witness cosignature from Python.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ORIGIN="${ORIGIN:-example.com/workshop}"
STORAGE_DIR="${STORAGE_DIR:-log}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
export ORIGIN STORAGE_DIR HTTP_ADDR

echo "== 1/4 Set up the witness keys and policy =="
./scripts/setup_witness.sh
echo

echo "== 2/4 Start the local witness =="
./scripts/run_witness.sh start
echo

echo "== 3/4 Start the log with witnessing enabled =="
./scripts/run_tesseract.sh stop >/dev/null 2>&1 || true
ADDITIONAL_SIGNER=out/witness/log-signer.key \
  WITNESS_POLICY=out/witness/policy.txt \
  ./scripts/run_tesseract.sh start
trap './scripts/run_tesseract.sh stop; ./scripts/run_witness.sh stop' EXIT
echo

echo "== 4/4 Submit a certificate and verify the cosigned checkpoint =="
python3 -m lab.cli demo --storage-dir "$STORAGE_DIR" --log-key out/log-key.pem
sleep 2
python3 -m lab.cli checkpoint \
  --storage-dir "$STORAGE_DIR" \
  --pubkey out/log-key.pem \
  --witness-vkey out/witness/witness-vkey.txt
echo
echo "The checkpoint now carries the log's signatures and a witness cosignature."
