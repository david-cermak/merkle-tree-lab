"""Build and size an "MTC-shaped" certificate bundle.

A conventional post-quantum certificate carries a large CA signature *inside
every certificate*. The Merkle Tree Certificate idea is to sign a Merkle root
once and let each certificate prove its inclusion with a small audit path plus
a signed checkpoint (and, in the full design, witness cosignatures).

This module does not implement the MTC wire format. It assembles the same
building blocks the lab already produces — certificate, inclusion proof, signed
checkpoint, signatures — into one JSON object so students can compare its size
against a conventional certificate chain and reason about amortization.

The bundle is a teaching artifact, not a standard.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Dict, List, Sequence

from . import note


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def build_bundle(
    certificate: bytes,
    leaf_index: int,
    tree_size: int,
    leaf_hash: bytes,
    audit_path: Sequence[bytes],
    checkpoint: note.Checkpoint,
    checkpoint_raw: bytes,
) -> Dict[str, object]:
    """Assemble an MTC-shaped bundle as a JSON-serialisable dict."""
    signatures: List[Dict[str, object]] = []
    for signature in checkpoint.signatures:
        role = "log" if signature.name == checkpoint.origin else "witness"
        signatures.append(
            {
                "name": signature.name,
                "key_hash": f"{signature.key_hash:08x}",
                "role": role,
                "signature": _b64(signature.raw),
            }
        )

    return {
        "version": 1,
        "leaf": {
            "certificate": _b64(certificate),
            "leaf_index": leaf_index,
            "leaf_hash": leaf_hash.hex(),
        },
        "inclusion_proof": {
            "tree_size": tree_size,
            "audit_path": [node.hex() for node in audit_path],
        },
        "checkpoint": {
            "origin": checkpoint.origin,
            "tree_size": checkpoint.size,
            "root_hash": checkpoint.root_hash.hex(),
            "note": _b64(checkpoint_raw),
            "signatures": signatures,
        },
    }


def serialise(bundle: Dict[str, object]) -> bytes:
    """Serialise a bundle the way it would travel on the wire (compact JSON)."""
    return json.dumps(bundle, separators=(",", ":")).encode()


def bundle_size(bundle: Dict[str, object]) -> int:
    return len(serialise(bundle))


def format_comparison(
    bundle: Dict[str, object], leaf_certificate: bytes, conventional_chain: bytes
) -> str:
    """Return a human-readable size comparison."""
    size = bundle_size(bundle)
    leaf = len(leaf_certificate)
    chain = len(conventional_chain)
    proof_nodes = len(bundle["inclusion_proof"]["audit_path"])  # type: ignore[index]
    lines = [
        "MTC-shaped bundle vs conventional PQC certificate",
        f"  conventional leaf certificate          : {leaf} bytes",
        f"  conventional chain (leaf+intermediate) : {chain} bytes",
        f"  MTC-shaped bundle (JSON, base64 cert)  : {size} bytes",
        f"  ratio (bundle / leaf)                  : {size / leaf:.2f}x" if leaf else "",
        f"  ratio (bundle / chain)                 : {size / chain:.2f}x" if chain else "",
        f"  audit path                             : {proof_nodes} hash(es)",
        "",
        "The bundle is JSON with a base64 certificate, which adds about 33%.",
        "For a single certificate the bundle may be larger or smaller than the",
        "conventional chain, depending on chain depth. The real win is at scale:",
        "one checkpoint signature is shared by every certificate in the tree, and",
        "each certificate carries only a short audit path instead of a full PQ",
        "signature.",
    ]
    return "\n".join(line for line in lines if line != "")


def write_bundle(bundle: Dict[str, object], path: str) -> int:
    data = serialise(bundle)
    Path(path).write_bytes(data + b"\n")
    return len(data)
