#!/usr/bin/env bash
# Generate the default set of certificate chains used for size measurement.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUTDIR="${OUTDIR:-out/pki}"
ALGORITHMS=("${@:-ecdsa-p256 rsa-2048 mldsa44 mldsa65 slhdsa-sha2-128s falcon512}")

for alg in "${ALGORITHMS[@]}"; do
  echo "==> $alg"
  python3 -m lab.cli pki --algorithm "$alg" --outdir "$OUTDIR"
done
