"""Measure certificate, key, and signature sizes across algorithms.

The measurements come straight from the DER bytes, so they work for classical
and post-quantum certificates alike. Reporting the same fields for every
algorithm makes the trade-offs visible:

* ``cert_der`` — the size of the leaf certificate on the wire.
* ``spki`` — the encoded public key (``SubjectPublicKeyInfo``).
* ``signature`` — the CA's signature value inside the leaf certificate.
* ``chain_der`` — leaf + intermediate, i.e. what a TLS client is sent.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import certs
from .pki import ALGORITHMS


@dataclass
class Measurement:
    algorithm: str
    label: str
    family: str
    cert_algorithm: str
    public_key_algorithm: str
    cert_der: int
    spki: int
    signature: int
    chain_der: int

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)


def measure_algorithm(directory: Path) -> Optional[Measurement]:
    """Measure one algorithm's chain, or return ``None`` if it is missing."""
    leaf_path = directory / "leaf.crt"
    int_path = directory / "int.crt"
    if not leaf_path.exists() or not int_path.exists():
        return None

    leaf_der = certs.read_certificate(str(leaf_path))
    int_der = certs.read_certificate(str(int_path))
    sizes = certs.certificate_sizes(leaf_der)

    algorithm = directory.name
    alg = ALGORITHMS.get(algorithm)
    return Measurement(
        algorithm=algorithm,
        label=alg.label if alg else algorithm,
        family=alg.family if alg else "unknown",
        cert_algorithm=sizes.signature_algorithm,
        public_key_algorithm=sizes.public_key_algorithm,
        cert_der=sizes.der_size,
        spki=sizes.spki_size,
        signature=sizes.signature_size,
        chain_der=sizes.der_size + len(int_der),
    )


def measure_directory(pki_dir: Path) -> List[Measurement]:
    """Measure every algorithm directory under ``pki_dir``."""
    results = []
    if not Path(pki_dir).is_dir():
        return results
    for directory in sorted(Path(pki_dir).iterdir()):
        if directory.is_dir():
            measurement = measure_algorithm(directory)
            if measurement:
                results.append(measurement)
    results.sort(key=lambda m: (m.family != "classical", m.cert_der))
    return results


def format_markdown(measurements: List[Measurement]) -> str:
    """Render the measurements as a Markdown table."""
    lines = [
        "| Algorithm | Family | Cert (DER) | Public key (SPKI) | Signature | Chain (leaf+int) |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for m in measurements:
        lines.append(
            f"| {m.label} | {m.family} | {m.cert_der} | {m.spki} | {m.signature} | {m.chain_der} |"
        )
    return "\n".join(lines) + "\n"


def write_reports(measurements: List[Measurement], json_path: Path, markdown_path: Path) -> None:
    json_path = Path(json_path)
    markdown_path = Path(markdown_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps([m.as_dict() for m in measurements], indent=2) + "\n")
    markdown_path.write_text(format_markdown(measurements))
