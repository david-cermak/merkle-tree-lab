#!/usr/bin/env bash
# End-to-end workshop happy path (also serves as the smoke test):
# measure, start the log, submit, fill the tree, walk the proof, verify the
# checkpoint, then build the MTC issuance log and emit the four certificate
# shapes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON="${PYTHON:-$(test -x .venv/bin/python && echo .venv/bin/python || echo python3)}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:6962}"
STORAGE_DIR="${STORAGE_DIR:-log}"
LOG_KEY="${LOG_KEY:-out/log-key.pem}"
MTC_DIR="${MTC_DIR:-out/mtc}"

echo "== 1/10 Generate the PKIs and measure sizes =="
"$PYTHON" -m lab.cli measure --generate
echo

echo "== 2/10 Start the local TesseraCT log =="
./scripts/run_tesseract.sh start
trap './scripts/run_tesseract.sh stop' EXIT
echo

echo "== 3/10 Submit a certificate and verify its inclusion proof =="
"$PYTHON" -m lab.cli demo \
  --algorithm mldsa65 \
  --log "http://${HTTP_ADDR}" \
  --storage-dir "${STORAGE_DIR}" \
  --log-key "${LOG_KEY}"
echo

echo "== 4/10 Give the log a real tree =="
echo "-- 'make demo' resubmits the same leaf, and the log deduplicates it, so"
echo "   the tree stays at size 1 and every proof has no siblings"
"$PYTHON" -m lab.cli fill \
  --algorithm mldsa65 \
  --count 8 \
  --log "http://${HTTP_ADDR}" \
  --storage-dir "${STORAGE_DIR}"
echo

echo "== 5/10 Walk two inclusion proofs hash by hash =="
echo "-- an inner path (mixed left and right siblings):"
"$PYTHON" -m lab.cli walk --storage-dir "${STORAGE_DIR}" --index 2
echo
echo "-- and a border path (all left siblings):"
"$PYTHON" -m lab.cli walk --storage-dir "${STORAGE_DIR}" --index 7
echo

echo "== 6/10 Verify the signed checkpoint =="
"$PYTHON" -m lab.cli checkpoint --storage-dir "${STORAGE_DIR}" --pubkey "${LOG_KEY}"
echo

echo "== 7/10 Build the MTC issuance log: 2 checkpoints + 1 landmark =="
"$PYTHON" -m lab.cli mtc lab --outdir "${MTC_DIR}" --entries 20 --log 8
echo

echo "== 8/10 Emit the four certificate shapes for entry 3 =="
"$PYTHON" -m lab.cli mtc shapes --outdir "${MTC_DIR}" --index 3
echo

echo "== 9/10 Verify the four shapes as a relying party, at three levels of knowledge =="
echo "-- with only the cosigner keys: the two cosigned shapes verify,"
echo "   the landmark shape is not yet checkable"
"$PYTHON" -m lab.cli mtc verify --outdir "${MTC_DIR}" --index 3 --knows cosigners
echo
echo "-- with the landmark as well: all three MTC shapes verify"
"$PYTHON" -m lab.cli mtc verify --outdir "${MTC_DIR}" --index 3 --knows landmark
echo
echo "== 10/10 Change one field and watch every shape refuse it =="
"$PYTHON" -m lab.cli mtc verify --outdir "${MTC_DIR}" --index 3 --knows all --tamper
echo
echo "Workshop happy path complete."
