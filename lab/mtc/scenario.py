"""The workshop scenario: one CA, one log, two checkpoints, one landmark.

The exercises all work against the same numbers -- log 8, 20 entries, a null
entry at index 7, checkpoints at tree sizes 12 and 20, a landmark at tree size
20 covering ``[0, 16)`` and ``[16, 20)``, and a certificate for index 3. Having
those fixed in one place is what makes the printed hashes comparable between
people's machines and between runs.

:func:`build` creates the scenario with real ML-DSA keys; :func:`save` and
:func:`load` write it as JSON so the three CLI commands can work in sequence.

The keys are stored, not regenerated, and that is deliberate. ML-DSA
signatures depend on a random nonce, so a second run with fresh keys would
produce different cosignatures for the same subtree, and a certificate written
by one command would not verify in the next. Persisting the keys makes the
commands a pipeline instead of three unrelated demonstrations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from .cosigners import (
    CertificateSigner,
    Cosigner,
)
from .ids import TrustAnchorID
from .landmarks import Landmark, LandmarkSequence
from .log import (
    LAB_EPOCH,
    NULL_ENTRY,
    TBS_CERT_ENTRY,
    IssuanceLog,
    MTCLogEntry,
    TbsCertificateLogEntry,
    null_entry,
)

#: The CA the workshop uses. The draft's own example CA is ``32473.1``; this one
#: is the audio book's, ``32473.100``, so the printed OIDs match the handouts.
CA_ID = TrustAnchorID.parse("32473.100")

#: Log 8, 20 entries, a null entry at 7, checkpoints at 12 and 20, a landmark at
#: 20, and a certificate for index 3. Every exercise quotes these.
LOG_NUMBER = 8
ENTRIES = 20
NULL_ENTRY_AT = 7
CHECKPOINT_SIZES = (12, 20)
LANDMARK_SIZE = 20
LANDMARK_EXPIRY = LAB_EPOCH + 3600
CERT_INDEX = 3

#: One year, in the lab's compressed validity encoding.
VALIDITY_SECONDS = 126 * 3600

#: The algorithm name as it appears in an entry or certificate body, the
#: spelling the draft uses. The parameter set names below (``mldsa44``,
#: ``mldsa65``) are the ``cryptography`` key-class names and never appear in a
#: certificate body.
SUBJECT_ALGORITHM = "ML-DSA-65"
SUBJECT_PARAMETER_SET = "mldsa65"
COSIGNER_ALGORITHM = "mldsa44"
SIGNER_PARAMETER_SET = "mldsa65"

_PRIVATE_FORMAT = (
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)


def _new_key(parameter_set: str):
    return {
        "mldsa44": mldsa.MLDSA44PrivateKey,
        "mldsa65": mldsa.MLDSA65PrivateKey,
    }[parameter_set].generate()


def _spki(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_key(der: bytes):
    return serialization.load_der_private_key(der, password=None)


@dataclass
class Scenario:
    """Everything the CLI and the exercises need, with the keys intact."""

    log: IssuanceLog
    cosigners: List[Cosigner]
    signer: CertificateSigner
    sequence: LandmarkSequence
    subject_keys: Dict[int, bytes] = field(default_factory=dict)

    @property
    def ca_id(self) -> TrustAnchorID:
        return self.log.ca_id

    @property
    def landmark(self) -> Landmark:
        return self.sequence.latest

    def spki(self, index: int) -> bytes:
        """Return the DER public key attested by the entry at ``index``."""
        return self.subject_keys[index]

    def checkpoint(self, tree_size: int):
        return self.log.checkpoint(tree_size, self.cosigners)

    @property
    def null_indices(self) -> List[int]:
        """The indices of the log's null entries, in order."""
        return [
            index
            for index, entry in enumerate(self.log.entries)
            if entry.type == NULL_ENTRY
        ]

    @property
    def checkpoint_sizes(self) -> List[int]:
        """The sizes this scenario checkpoints at, clipped to the log."""
        return [size for size in CHECKPOINT_SIZES if size <= self.log.size]

    def describe(self) -> List[str]:
        """Return the lines ``mtc lab`` prints.

        Everything is read off the scenario rather than off the module
        constants, so a scenario built with non-default ``entries`` or
        ``null_at`` still describes itself correctly.
        """
        cert_index = CERT_INDEX if CERT_INDEX in self.subject_keys else 0
        empty = not self.log.size
        lines = [
            f"CA ID                {self.ca_id.dotted}",
            f"issuance log         {self.log.log_id.dotted} (log {self.log.log_number})",
            f"entries              {self.log.size}",
            f"null entry at index  {', '.join(str(i) for i in self.null_indices) or 'none'}",
        ]
        if empty:
            # An empty log has no entry to hash and no certificate to point at.
            # The lab never builds one -- the smallest interesting question is
            # whether a short log still gets checkpoints and a landmark -- but
            # saying so is better than an IndexError from the describe path.
            lines.append("leaf hashes           (none: the log is empty)")
        elif cert_index == 0:
            lines.append(f"leaf hash of index 0 {self.log.entry_hash(0).hex()}")
        else:
            lines += [
                f"leaf hash of index 0 {self.log.entry_hash(0).hex()}",
                f"leaf hash of index {cert_index} {self.log.entry_hash(cert_index).hex()}",
            ]
        lines += [
            "",
            "checkpoints (timestamped cosignatures over [0, size)):",
        ]
        for size in self.checkpoint_sizes:
            checkpoint = self.checkpoint(size)
            lines.append(
                f"  size {size:>3}  root {checkpoint.root_hash.hex()[:32]}...  "
                f"{len(checkpoint.signatures)} cosignatures "
                f"({', '.join(s.cosigner_id.short for s in checkpoint.signatures)})"
            )
        if not self.checkpoint_sizes:
            lines.append("  (none: the log is shorter than every checkpoint size)")
        if len(self.sequence):
            landmark = self.landmark
            lines += [
                "",
                f"landmark {landmark.number}          tree size "
                f"{landmark.tree_size}, expires {landmark.expiry}",
                f"  landmark subtrees   "
                f"{', '.join(f'[{s}, {e})' for s, e in landmark.subtrees)}",
            ]
            for start, end in landmark.subtrees:
                lines.append(
                    f"  [{start}, {end}) hashes to {self.log.subtree_hash(start, end).hex()}"
                )
        else:
            lines += ["", "landmark                (none: no landmark published yet)"]
        if empty:
            return lines + ["", "certificate             (none: the log is empty)"]
        lines += [
            "",
            f"certificate index    {cert_index} (serial {self.log.serial(cert_index)})",
            f"  the log entry      {len(self.log.entries[cert_index].encoded())} bytes, "
            f"hashed to {len(self.log.entry_hash(cert_index))} bytes",
        ]
        if cert_index in self.subject_keys:
            lines.append(
                f"  a CT-style entry   would instead carry the whole "
                f"{len(self.subject_keys[cert_index])}-byte public key and a signature"
            )
        return lines


def _subject_name(index: int) -> str:
    return f"www{index}.example"


def build(
    entries: int = ENTRIES,
    log_number: int = LOG_NUMBER,
    null_at: Optional[int] = NULL_ENTRY_AT,
    key_reuse: int = 3,
) -> Scenario:
    """Create the workshop scenario with freshly generated real keys.

    ``key_reuse`` is how many distinct subject keys to generate before reusing
    one. Generating twenty ML-DSA-65 keys costs real time and adds nothing to the
    teaching value -- the log stores only their hashes -- so the default is a
    handful of real keys shared across the log. Pass ``entries`` for one key per
    entry when a test needs every subject to differ.
    """
    log = IssuanceLog(CA_ID, log_number)
    subject_keys: Dict[int, bytes] = {}
    key_count = entries if key_reuse is None else min(key_reuse, entries)
    keys = [_spki(_new_key(SUBJECT_PARAMETER_SET)) for _ in range(key_count)]

    for index in range(entries):
        if index == null_at:
            log.append(null_entry())
            continue
        key = keys[index % key_count]
        subject_keys[index] = key
        log.append(
            MTCLogEntry(
                type=TBS_CERT_ENTRY,
                tbs_certificate=TbsCertificateLogEntry(
                    issuer=CA_ID,
                    subject=_subject_name(index),
                    subject_public_key_algorithm=SUBJECT_ALGORITHM,
                    subject_public_key_info_hash=_hash_of(key),
                    not_before=LAB_EPOCH,
                    not_after=LAB_EPOCH + VALIDITY_SECONDS,
                    subject_alt_names=(_subject_name(index), "example.com"),
                ),
            )
        )

    cosigners = [
        Cosigner(CA_ID, _new_key(COSIGNER_ALGORITHM), "CA", COSIGNER_ALGORITHM),
        Cosigner(
            CA_ID.landmark(log_number, 1),
            _new_key(COSIGNER_ALGORITHM),
            "witness",
            COSIGNER_ALGORITHM,
        ),
    ]
    signer = CertificateSigner(CA_ID, SIGNER_PARAMETER_SET)
    signer.private_key = _new_key(SIGNER_PARAMETER_SET)

    sequence = LandmarkSequence(log.log_id)
    landmark_size = min(LANDMARK_SIZE, log.size)
    if landmark_size > 0:
        sequence.append(landmark_size, LANDMARK_EXPIRY)

    return Scenario(
        log=log,
        cosigners=cosigners,
        signer=signer,
        sequence=sequence,
        subject_keys=subject_keys,
    )


def _hash_of(spki: bytes) -> bytes:
    return hashlib.sha256(spki).digest()


def to_dict(scenario: Scenario) -> dict:
    """Serialise a scenario, keys included, to a JSON-compatible dict."""
    return {
        "format": "mtc-lab-scenario/1",
        "ca_id": scenario.ca_id.dotted,
        "log_number": scenario.log.log_number,
        "log_id": scenario.log.log_id.dotted,
        "landmark_expiry": LANDMARK_EXPIRY,
        "entries": [
            None
            if entry.type == NULL_ENTRY
            else {
                "subject": entry.tbs_certificate.subject,
                "algorithm": entry.tbs_certificate.subject_public_key_algorithm,
                "spki_hash": entry.tbs_certificate.subject_public_key_info_hash.hex(),
                "not_before": entry.tbs_certificate.not_before,
                "not_after": entry.tbs_certificate.not_after,
                "sans": list(entry.tbs_certificate.subject_alt_names),
                "entry_hash": entry.entry_hash().hex(),
            }
            for entry in scenario.log.entries
        ],
        "subject_keys": {
            str(index): key.hex() for index, key in scenario.subject_keys.items()
        },
        "cosigners": [
            {
                "cosigner_id": cosigner.cosigner_id.dotted,
                "role": cosigner.role,
                "parameter_set": cosigner.parameter_set,
                "private_key": cosigner.private_key.private_bytes(*_PRIVATE_FORMAT).hex(),
            }
            for cosigner in scenario.cosigners
        ],
        "signer": {
            "ca_id": scenario.signer.ca_id.dotted,
            "parameter_set": scenario.signer.parameter_set,
            "private_key": scenario.signer.private_key.private_bytes(*_PRIVATE_FORMAT).hex(),
        },
        "landmarks": [
            {
                "number": landmark.number,
                "tree_size": landmark.tree_size,
                "expiry": landmark.expiry,
                "subtrees": [list(pair) for pair in landmark.subtrees],
            }
            for landmark in scenario.sequence
        ],
    }


def from_dict(data: dict) -> Scenario:
    """Rebuild a scenario from :func:`to_dict`, restoring the exact keys."""
    ca_id = TrustAnchorID.parse(data["ca_id"])
    log = IssuanceLog(ca_id, data["log_number"])
    for index, entry in enumerate(data["entries"]):
        if entry is None:
            log.append(null_entry())
            continue
        log.append(
            MTCLogEntry(
                type=TBS_CERT_ENTRY,
                tbs_certificate=TbsCertificateLogEntry(
                    issuer=ca_id,
                    subject=entry["subject"],
                    subject_public_key_algorithm=entry["algorithm"],
                    subject_public_key_info_hash=bytes.fromhex(entry["spki_hash"]),
                    not_before=entry["not_before"],
                    not_after=entry["not_after"],
                    subject_alt_names=tuple(entry["sans"]),
                ),
            )
        )

    sequence = LandmarkSequence(log.log_id)
    for landmark in data["landmarks"][1:]:
        sequence.append(landmark["tree_size"], landmark["expiry"])

    cosigners = [
        Cosigner(
            cosigner_id=TrustAnchorID.parse(record["cosigner_id"]),
            private_key=_load_key(bytes.fromhex(record["private_key"])),
            role=record["role"],
            parameter_set=record["parameter_set"],
        )
        for record in data["cosigners"]
    ]
    signer = CertificateSigner(ca_id, data["signer"]["parameter_set"])
    signer.private_key = _load_key(bytes.fromhex(data["signer"]["private_key"]))

    return Scenario(
        log=log,
        cosigners=cosigners,
        signer=signer,
        sequence=sequence,
        subject_keys={
            int(index): bytes.fromhex(key)
            for index, key in data["subject_keys"].items()
        },
    )


def save(scenario: Scenario, outdir) -> Path:
    """Write the scenario to ``<outdir>/scenario.json`` and return the path."""
    directory = Path(outdir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "scenario.json"
    path.write_text(json.dumps(to_dict(scenario), indent=2) + "\n")
    return path


def load(outdir) -> Scenario:
    """Read a scenario written by :func:`save`."""
    path = Path(outdir) / "scenario.json"
    if not path.exists():
        raise FileNotFoundError(
            f"no scenario at {path}; run 'lab.cli mtc lab --outdir {Path(outdir).parent}' first"
        )
    return from_dict(json.loads(path.read_text()))


def write_text(outdir, name: str, text: str) -> Path:
    """Write one text artefact next to the scenario and return its path."""
    directory = Path(outdir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text)
    return path
