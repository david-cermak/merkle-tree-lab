#!/usr/bin/env bash
# Generate the keys and policy needed for native Tessera witnessing.
#
# Creates, under out/witness/:
#   log-signer.key   Ed25519 note signer used by TesseraCT (--additional_signer)
#   log-vkey.txt     its verifier key, trusted by the witness
#   witness.key      Ed25519 note signer used by the witness
#   witness-vkey.txt its CosignatureV1 verifier key, referenced by the policy
#   policy.txt       witness policy for TesseraCT (--witness_policy_file)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ORIGIN="${ORIGIN:-example.com/workshop}"
WITNESS_NAME="${WITNESS_NAME:-witness.local}"
WITNESS_URL="${WITNESS_URL:-http://127.0.0.1:8100}"
WITNESS_DIR="${WITNESS_DIR:-out/witness}"
BIN="${BIN:-bin/witness}"

if [[ ! -x "$BIN" ]]; then
  echo "Building witness tool (Go ${GOTOOLCHAIN:-go1.27.0}) ..."
  (cd tools/witness && GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.0}" go build -o "../../$BIN" .)
fi

mkdir -p "$WITNESS_DIR"

if [[ ! -f "$WITNESS_DIR/log-signer.key" ]]; then
  echo "Generating log additional-signer key ($ORIGIN) ..."
  "$BIN" keygen --name "$ORIGIN" --out "$WITNESS_DIR/log-signer.key" >"$WITNESS_DIR/log.keys"
  sed -n '1p' "$WITNESS_DIR/log.keys" >"$WITNESS_DIR/log-vkey.txt"
fi

if [[ ! -f "$WITNESS_DIR/witness.key" ]]; then
  echo "Generating witness key ($WITNESS_NAME) ..."
  "$BIN" keygen --name "$WITNESS_NAME" --out "$WITNESS_DIR/witness.key" >"$WITNESS_DIR/witness.keys"
  sed -n '2p' "$WITNESS_DIR/witness.keys" >"$WITNESS_DIR/witness-vkey.txt"
fi

printf 'witness w1 %s %s\nquorum w1\n' "$(cat "$WITNESS_DIR/witness-vkey.txt")" "$WITNESS_URL" \
  >"$WITNESS_DIR/policy.txt"

echo "Witness configuration ready in $WITNESS_DIR/"
echo "  log signer : $WITNESS_DIR/log-signer.key"
echo "  log vkey   : $WITNESS_DIR/log-vkey.txt"
echo "  witness key: $WITNESS_DIR/witness.key"
echo "  policy     : $WITNESS_DIR/policy.txt"
