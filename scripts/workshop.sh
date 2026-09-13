#!/usr/bin/env bash
# End-to-end workshop happy path (also serves as the smoke test):
# measure, start the log, submit, walk the proof, verify, and size a bundle.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
STORAGE_DIR="${STORAGE_DIR:-log}"
LOG_KEY="${LOG_KEY:-out/log-key.pem}"

echo "== 1/6 Generate the PKIs and measure sizes =="
python3 -m lab.cli measure --generate
echo

echo "== 2/6 Start the local TesseraCT log =="
./scripts/run_tesseract.sh start
trap './scripts/run_tesseract.sh stop' EXIT
echo

echo "== 3/6 Submit a certificate and verify its inclusion proof =="
python3 -m lab.cli demo \
  --algorithm mldsa65 \
  --log "http://${HTTP_ADDR}" \
  --storage-dir "${STORAGE_DIR}" \
  --log-key "${LOG_KEY}"
echo

echo "== 4/6 Walk the inclusion proof hash by hash =="
python3 -m lab.cli walk --storage-dir "${STORAGE_DIR}" --index 0
echo

echo "== 5/6 Verify the signed checkpoint =="
python3 -m lab.cli checkpoint --storage-dir "${STORAGE_DIR}" --pubkey "${LOG_KEY}"
echo

echo "== 6/6 Build and size an MTC-shaped bundle =="
python3 -m lab.cli bundle --storage-dir "${STORAGE_DIR}" --index 0 --output out/mtc_bundle.json
echo
echo "Workshop happy path complete."
