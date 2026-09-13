#!/usr/bin/env bash
# End-to-end workshop happy path: measure, start the log, submit, verify.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
STORAGE_DIR="${STORAGE_DIR:-log}"
LOG_KEY="${LOG_KEY:-out/log-key.pem}"

echo "== 1/3 Generate the PKIs and measure sizes =="
python3 -m lab.cli measure --generate
echo

echo "== 2/3 Start the local TesseraCT log =="
./scripts/run_tesseract.sh start
trap './scripts/run_tesseract.sh stop' EXIT
echo

echo "== 3/3 Submit a certificate and verify its inclusion proof =="
python3 -m lab.cli demo \
  --algorithm mldsa65 \
  --log "http://${HTTP_ADDR}" \
  --storage-dir "${STORAGE_DIR}" \
  --log-key "${LOG_KEY}"
echo
echo "Workshop happy path complete."
