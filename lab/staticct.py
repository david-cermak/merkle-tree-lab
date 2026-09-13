"""Client for TesseraCT's static-ct-api and tlog-tiles storage.

TesseraCT exposes two different surfaces:

* **Submission** over HTTP JSON at ``/ct/v1/add-chain`` and ``/ct/v1/get-roots``.
* **Monitoring** as static files: a signed ``checkpoint`` and Merkle
  ``tile/data/*`` entry bundles under the log's storage directory.

There is no "get proof" RPC. A client reads the entry bundles, rebuilds the
Merkle tree from the logged entries, and derives inclusion proofs itself. For a
workshop-sized log that is cheap and very explicit, which is exactly what we
want to teach.

The entry-bundle byte layout (from TesseraCT's ``ctonly.Entry``) is::

    x509 entry:    timestamp(8) || entry_type=0(2)
                   || uint24(cert) || uint16(extensions) || uint16(fingerprints)
    precert entry: timestamp(8) || entry_type=1(2) || issuer_key_hash(32)
                   || uint24(tbs) || uint16(extensions) || uint24(precert)
                   || uint16(fingerprints)

The RFC 6962 ``MerkleTreeLeaf`` that actually gets hashed drops the
fingerprints and adds the two leading bytes (version, leaf type)::

    0x00 || 0x00 || timestamp(8) || entry_type(2) || uint24(cert) || uint16(extensions)
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import merkle

ENTRY_BUNDLE_WIDTH = 256


@dataclass
class Entry:
    """A single logged CT entry."""

    timestamp: int
    is_precert: bool
    certificate: bytes
    extensions: bytes
    fingerprints: bytes
    leaf_index: int
    issuer_key_hash: Optional[bytes] = None
    precertificate: Optional[bytes] = None
    _leaf_hash: Optional[bytes] = field(default=None, repr=False)

    def merkle_tree_leaf(self) -> bytes:
        """Return the RFC 6962 ``MerkleTreeLeaf`` bytes for this entry."""
        out = bytearray(b"\x00\x00")  # version=v1, leaf_type=timestamped_entry
        out += self.timestamp.to_bytes(8, "big")
        if self.is_precert:
            out += (1).to_bytes(2, "big")
            out += self.issuer_key_hash or b""
            out += len(self.certificate).to_bytes(3, "big") + self.certificate
        else:
            out += (0).to_bytes(2, "big")
            out += len(self.certificate).to_bytes(3, "big") + self.certificate
        out += len(self.extensions).to_bytes(2, "big") + self.extensions
        return bytes(out)

    def leaf_hash(self) -> bytes:
        if self._leaf_hash is None:
            self._leaf_hash = merkle.hash_leaf(self.merkle_tree_leaf())
        return self._leaf_hash


def parse_ct_extensions(extensions: bytes) -> int:
    """Extract the leaf index embedded in the static-ct CT extensions."""
    if len(extensions) < 3 or extensions[0] != 0:
        raise ValueError("unexpected CT extension encoding")
    length = int.from_bytes(extensions[1:3], "big")
    data = extensions[3 : 3 + length]
    if len(data) != 5:
        raise ValueError("leaf index extension must be 5 bytes")
    return int.from_bytes(data, "big")


def _read_uint(data: bytes, offset: int, size: int) -> tuple[int, int]:
    end = offset + size
    if end > len(data):
        raise ValueError("truncated entry bundle")
    return int.from_bytes(data[offset:end], "big"), end


def parse_entry_bundle(data: bytes) -> List[Entry]:
    """Parse a ``tile/data`` entry bundle into a list of entries."""
    entries: List[Entry] = []
    offset = 0
    while offset < len(data):
        timestamp, offset = _read_uint(data, offset, 8)
        entry_type, offset = _read_uint(data, offset, 2)

        if entry_type == 0:
            cert_len, offset = _read_uint(data, offset, 3)
            certificate = data[offset : offset + cert_len]
            offset += cert_len
            ext_len, offset = _read_uint(data, offset, 2)
            extensions = data[offset : offset + ext_len]
            offset += ext_len
            fp_len, offset = _read_uint(data, offset, 2)
            fingerprints = data[offset : offset + fp_len]
            offset += fp_len
            entries.append(
                Entry(
                    timestamp=timestamp,
                    is_precert=False,
                    certificate=certificate,
                    extensions=extensions,
                    fingerprints=fingerprints,
                    leaf_index=parse_ct_extensions(extensions),
                )
            )
        elif entry_type == 1:
            issuer_key_hash = data[offset : offset + 32]
            offset += 32
            tbs_len, offset = _read_uint(data, offset, 3)
            tbs = data[offset : offset + tbs_len]
            offset += tbs_len
            ext_len, offset = _read_uint(data, offset, 2)
            extensions = data[offset : offset + ext_len]
            offset += ext_len
            precert_len, offset = _read_uint(data, offset, 3)
            precertificate = data[offset : offset + precert_len]
            offset += precert_len
            fp_len, offset = _read_uint(data, offset, 2)
            fingerprints = data[offset : offset + fp_len]
            offset += fp_len
            entries.append(
                Entry(
                    timestamp=timestamp,
                    is_precert=True,
                    certificate=tbs,
                    extensions=extensions,
                    fingerprints=fingerprints,
                    leaf_index=parse_ct_extensions(extensions),
                    issuer_key_hash=issuer_key_hash,
                    precertificate=precertificate,
                )
            )
        else:
            raise ValueError(f"unknown entry type {entry_type}")
    return entries


def format_n(index: int) -> str:
    """Format a tile/bundle index the way tlog-tiles does."""
    if index < 1000:
        return f"{index:03d}"
    return f"x{(index // 1000) % 1000:03d}/{index % 1000:03d}"


def read_entry_bundles(storage_dir: str) -> List[Entry]:
    """Read every entry bundle under ``<storage_dir>/tile/data`` in order."""
    base = Path(storage_dir) / "tile" / "data"
    entries: List[Entry] = []
    if not base.is_dir():
        return entries
    for path in sorted(base.iterdir()):
        if path.is_file():
            entries.extend(parse_entry_bundle(path.read_bytes()))
        elif path.is_dir() and path.name.endswith(".p"):
            widths = sorted(int(p.name) for p in path.iterdir() if p.name.isdigit())
            if widths:
                entries.extend(parse_entry_bundle((path / str(widths[-1])).read_bytes()))
    return entries


class StaticCTClient:
    """Talk to a local TesseraCT POSIX log."""

    def __init__(self, base_url: str, storage_dir: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.storage_dir = storage_dir

    # -- submission ---------------------------------------------------------
    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.base_url + path, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"{path} failed: HTTP {exc.code}: {detail}") from exc

    def add_chain(self, chain_der: List[bytes]) -> dict:
        """Submit a certificate chain and return the SCT response."""
        import base64

        payload = {"chain": [base64.b64encode(der).decode() for der in chain_der]}
        return self._post("/ct/v1/add-chain", payload)

    def get_roots(self) -> List[bytes]:
        """Fetch the roots the log is willing to accept."""
        import base64

        with urllib.request.urlopen(self.base_url + "/ct/v1/get-roots", timeout=30) as response:
            data = json.loads(response.read())
        return [base64.b64decode(cert) for cert in data["certificates"]]

    # -- monitoring ---------------------------------------------------------
    def checkpoint_bytes(self) -> bytes:
        """Read the raw signed checkpoint from storage."""
        if not self.storage_dir:
            raise ValueError("storage_dir is required to read the checkpoint")
        return (Path(self.storage_dir) / "checkpoint").read_bytes()

    def entries(self) -> List[Entry]:
        """Read all logged entries from the entry bundles."""
        if not self.storage_dir:
            raise ValueError("storage_dir is required to read entries")
        return read_entry_bundles(self.storage_dir)

    def leaf_hashes(self) -> List[bytes]:
        return [entry.leaf_hash() for entry in self.entries()]

    def root(self) -> bytes:
        return merkle.root_from_hashes(self.leaf_hashes())

    def inclusion_proof(self, index: int) -> List[bytes]:
        return merkle.inclusion_proof(self.leaf_hashes(), index)

    def wait_for_size(self, size: int, timeout: float = 30.0, interval: float = 0.25) -> int:
        """Wait until the checkpoint reports at least ``size`` leaves."""
        from . import note

        deadline = time.time() + timeout
        last = 0
        while time.time() < deadline:
            checkpoint = note.parse_checkpoint(self.checkpoint_bytes())
            last = checkpoint.size
            if last >= size:
                return last
            time.sleep(interval)
        raise TimeoutError(f"log size stayed at {last}, wanted >= {size}")
