"""Signed checkpoints ("notes") and their verification.

TesseraCT publishes its current tree state as a *checkpoint*, in the
``golang.org/x/mod/sumdb/note`` text format::

    <origin>
    <tree_size>
    <base64 root hash>
    <blank line>
    — <origin> <base64 signature>

The first three lines are the signed message. Each signature line carries a
4-byte key hash, then an 8-byte timestamp, then a TLS-encoded signature over an
RFC 6962 ``TreeHeadSignature`` structure::

    version(1)=0 || signature_type(1)=1 || timestamp(8) || tree_size(8) || root_hash(32)

This module parses the checkpoint and verifies the ECDSA signature using the
log's public key. Verification needs the ``cryptography`` package; parsing does
not.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import List

SIGNATURE_TYPE_TREE_HASH = 0x01
HASH_ALG_SHA256 = 0x04
SIG_ALG_ECDSA = 0x03
KEY_HASH_SIZE = 4
TIMESTAMP_SIZE = 8


@dataclass
class NoteSignature:
    """One signature line of a note."""

    name: str
    key_hash: int
    raw: bytes

    @property
    def timestamp(self) -> int:
        return int.from_bytes(self.raw[KEY_HASH_SIZE : KEY_HASH_SIZE + TIMESTAMP_SIZE], "big")


@dataclass
class Checkpoint:
    """A parsed signed checkpoint."""

    origin: str
    size: int
    root_hash: bytes
    text: bytes
    signatures: List[NoteSignature] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"origin={self.origin} size={self.size} "
            f"root={self.root_hash.hex()} signatures={len(self.signatures)}"
        )


def _split_note(data: bytes):
    """Split a note into its signed text and signature lines."""
    lines = data.decode("utf-8").split("\n")
    sig_lines = [line for line in lines if line.startswith("\u2014 ")]
    if not sig_lines:
        return data.decode("utf-8"), []
    first_sig = next(i for i, line in enumerate(lines) if line.startswith("\u2014 "))
    text_lines = lines[:first_sig]
    while text_lines and text_lines[-1] == "":
        text_lines.pop()
    text = "\n".join(text_lines) + "\n"
    return text, sig_lines


def _parse_signature(line: str) -> NoteSignature:
    parts = line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"malformed signature line: {line!r}")
    _, name, encoded = parts
    raw = base64.b64decode(encoded)
    if len(raw) < KEY_HASH_SIZE:
        raise ValueError("signature too short")
    return NoteSignature(name=name, key_hash=int.from_bytes(raw[:KEY_HASH_SIZE], "big"), raw=raw)


def parse_checkpoint(data: bytes) -> Checkpoint:
    """Parse a signed checkpoint from raw bytes."""
    text, sig_lines = _split_note(data)
    lines = text.split("\n")
    if len(lines) < 3:
        raise ValueError("checkpoint must have at least three lines")
    origin = lines[0]
    size = int(lines[1])
    root_hash = base64.b64decode(lines[2])
    if len(root_hash) != 32:
        raise ValueError(f"unexpected root hash length: {len(root_hash)}")
    signatures = [_parse_signature(line) for line in sig_lines]
    return Checkpoint(
        origin=origin,
        size=size,
        root_hash=root_hash,
        text=text.encode(),
        signatures=signatures,
    )


def tree_head_signature_input(timestamp: int, size: int, root_hash: bytes) -> bytes:
    """Build the RFC 6962 ``TreeHeadSignature`` bytes that get signed."""
    return (
        bytes([0, SIGNATURE_TYPE_TREE_HASH])
        + timestamp.to_bytes(8, "big")
        + size.to_bytes(8, "big")
        + root_hash
    )


def compute_key_hash(origin: str, public_key) -> int:
    """Compute the note key hash for a log's ECDSA public key.

    ``key_hash = first 4 bytes of SHA256(origin || "\\n" || 0x05 || SHA256(SPKI))``
    """
    from cryptography.hazmat.primitives import serialization

    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = hashlib.sha256(spki).digest()
    digest = hashlib.sha256(origin.encode() + b"\n" + bytes([0x05]) + log_id).digest()
    return int.from_bytes(digest[:4], "big")


def load_public_key(path: str):
    """Load an ECDSA public key from a PEM file (public or private key)."""
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as fh:
        data = fh.read()
    if b"PRIVATE KEY" in data:
        private = serialization.load_pem_private_key(data, password=None)
        return private.public_key()
    return serialization.load_pem_public_key(data)


def verify_checkpoint(checkpoint: Checkpoint, public_key) -> bool:
    """Return ``True`` if any signature verifies against ``public_key``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    expected_hash = compute_key_hash(checkpoint.origin, public_key)

    for signature in checkpoint.signatures:
        raw = signature.raw
        if len(raw) < 16:
            continue
        if signature.key_hash != expected_hash:
            continue
        timestamp = int.from_bytes(raw[4:12], "big")
        hash_alg, sig_alg = raw[12], raw[13]
        sig_len = int.from_bytes(raw[14:16], "big")
        sig_bytes = raw[16 : 16 + sig_len]
        if hash_alg != HASH_ALG_SHA256 or sig_alg != SIG_ALG_ECDSA:
            continue
        if len(sig_bytes) != sig_len:
            continue
        digest = hashlib.sha256(
            tree_head_signature_input(timestamp, checkpoint.size, checkpoint.root_hash)
        ).digest()
        try:
            public_key.verify(sig_bytes, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            continue
    return False


def read_checkpoint(path: str) -> Checkpoint:
    """Read and parse a checkpoint file."""
    with open(path, "rb") as fh:
        return parse_checkpoint(fh.read())


# --- witness cosignatures -------------------------------------------------
#
# A witness cosignature (C2SP tlog-cosignature) is an Ed25519 signature over
#
#     cosignature/v1
#     time <unix seconds>
#     <the checkpoint note text>
#
# and is stored in the note signature line as
#
#     key hash (4) || timestamp (8) || ed25519 signature (64)
#
# The witness's verifier key is a note vkey whose key byte is 0x04
# (Ed25519CosignatureV1). A plain Ed25519 key (0x01) is normalised to 0x04
# before hashing.

COSIG_ALG_ED25519 = 0x01
COSIG_ALG_ED25519_V1 = 0x04


def parse_vkey(vkey: str) -> tuple[str, int, bytes]:
    """Parse a note verifier key into ``(name, algorithm, key_bytes)``."""
    parts = vkey.strip().split("+", 2)
    if len(parts) != 3:
        raise ValueError(f"malformed verifier key: {vkey!r}")
    name, _hash, encoded = parts
    raw = base64.b64decode(encoded)
    if not raw:
        raise ValueError("empty key")
    return name, raw[0], raw[1:]


def cosignature_key_hash(name: str, key_bytes: bytes) -> int:
    """Compute the note key hash for an Ed25519CosignatureV1 key."""
    digest = hashlib.sha256(
        name.encode() + b"\n" + bytes([COSIG_ALG_ED25519_V1]) + key_bytes
    ).digest()
    return int.from_bytes(digest[:4], "big")


def verify_cosignature(checkpoint: Checkpoint, vkey: str) -> bool:
    """Verify a witness cosignature on ``checkpoint`` against a note vkey.

    Accepts either a plain Ed25519 vkey (type 0x01) or an
    Ed25519CosignatureV1 vkey (type 0x04).
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    name, algorithm, key_bytes = parse_vkey(vkey)
    if algorithm not in (COSIG_ALG_ED25519, COSIG_ALG_ED25519_V1):
        return False
    if len(key_bytes) != 32:
        return False

    expected_hash = cosignature_key_hash(name, key_bytes)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    for signature in checkpoint.signatures:
        raw = signature.raw
        if signature.name != name or signature.key_hash != expected_hash:
            continue
        if len(raw) != KEY_HASH_SIZE + TIMESTAMP_SIZE + 64:
            continue
        timestamp = int.from_bytes(raw[KEY_HASH_SIZE : KEY_HASH_SIZE + TIMESTAMP_SIZE], "big")
        signed = b"cosignature/v1\ntime %d\n" % timestamp + checkpoint.text
        try:
            public_key.verify(raw[KEY_HASH_SIZE + TIMESTAMP_SIZE :], signed)
            return True
        except InvalidSignature:
            continue
    return False
