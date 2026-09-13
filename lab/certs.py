"""Certificate loading and size measurement.

Post-quantum certificates cannot always be parsed by third-party libraries
(``cryptography`` did not understand ML-DSA at the time of writing), so this
module keeps certificate handling deliberately low-level:

* PEM is just base64 wrapped in ``-----BEGIN CERTIFICATE-----`` markers.
* Sizes are read straight out of the DER structure with a tiny ASN.1 parser.

That also makes the size story explicit: a certificate is a ``SEQUENCE`` of
three things — the TBS certificate, the signature algorithm, and the signature
itself. The jump in PQC certificate size comes from the public key inside the
TBS certificate and from the signature value.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL
)

# OIDs we expect to meet in the workshop, mapped to human-readable names.
_SIGNATURE_ALGORITHMS = {
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.3.101.112": "Ed25519",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

_PUBLIC_KEY_ALGORITHMS = {
    "1.2.840.10045.2.1": "EC",
    "1.2.840.113549.1.1.1": "RSA",
    "1.3.101.112": "Ed25519",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


def pem_blocks(data: bytes, label: Optional[str] = None) -> List[Tuple[str, bytes]]:
    """Return ``(label, der)`` pairs for every PEM block in ``data``."""
    out = []
    for match in _PEM_RE.finditer(data):
        block_label = match.group(1).decode()
        if label is not None and block_label != label:
            continue
        der = base64.b64decode(re.sub(rb"\s+", b"", match.group(2)))
        out.append((block_label, der))
    return out


def read_certificates(path: str) -> List[bytes]:
    """Read every certificate in a PEM (or raw DER) file as DER bytes."""
    with open(path, "rb") as fh:
        data = fh.read()
    if b"-----BEGIN" not in data:
        return [data]
    return [der for _, der in pem_blocks(data, "CERTIFICATE")]


def read_certificate(path: str) -> bytes:
    """Read the first certificate in a file as DER bytes."""
    certs = read_certificates(path)
    if not certs:
        raise ValueError(f"no certificate found in {path}")
    return certs[0]


def der_to_pem(der: bytes, label: str = "CERTIFICATE") -> bytes:
    """Wrap DER bytes in PEM markers."""
    body = base64.encodebytes(der).replace(b"\n", b"")
    wrapped = b"\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return b"-----BEGIN " + label.encode() + b"-----\n" + wrapped + b"\n-----END " + label.encode() + b"-----\n"


def _read_tlv(data: bytes, offset: int) -> Tuple[int, int, int]:
    """Read one DER TLV at ``offset``; return ``(tag, value_start, value_end)``."""
    if offset >= len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        nbytes = first & 0x7F
        if nbytes == 0 or offset + nbytes > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    value_end = offset + length
    if value_end > len(data):
        raise ValueError("DER value exceeds buffer")
    return tag, offset, value_end


def _iter_tlvs(data: bytes):
    """Yield ``(tag, value_bytes, full_tlv_length)`` for the TLVs in ``data``."""
    offset = 0
    while offset < len(data):
        tag, value_start, value_end = _read_tlv(data, offset)
        yield tag, data[value_start:value_end], value_end - offset
        offset = value_end


def _decode_oid(data: bytes) -> str:
    """Decode a DER OBJECT IDENTIFIER value to dotted-decimal form."""
    if not data:
        return ""
    first = data[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


@dataclass
class CertificateSizes:
    """The size breakdown of a single X.509 certificate."""

    der_size: int
    tbs_size: int
    spki_size: int
    signature_size: int
    signature_algorithm: str
    public_key_algorithm: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "der_size": self.der_size,
            "tbs_size": self.tbs_size,
            "spki_size": self.spki_size,
            "signature_size": self.signature_size,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
        }


def _algorithm_oid(algorithm_identifier: bytes) -> str:
    """Return the OID from an ``AlgorithmIdentifier`` value."""
    for tag, value, _ in _iter_tlvs(algorithm_identifier):
        if tag == 0x06:  # OBJECT IDENTIFIER
            return _decode_oid(value)
    return ""


def _spki_algorithm_oid(spki_value: bytes) -> str:
    """Return the OID from a ``SubjectPublicKeyInfo`` value.

    ``SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, ... }``
    so the first child is the nested ``AlgorithmIdentifier``.
    """
    for tag, value, _ in _iter_tlvs(spki_value):
        if tag == 0x30:  # SEQUENCE (AlgorithmIdentifier)
            return _algorithm_oid(value)
    return ""


def certificate_sizes(der: bytes) -> CertificateSizes:
    """Parse the size-relevant fields out of a DER certificate.

    The X.509 layout is::

        Certificate ::= SEQUENCE {
            tbsCertificate   TBSCertificate,
            signatureAlgorithm AlgorithmIdentifier,
            signatureValue   BIT STRING
        }

    Inside the TBS certificate, the ``SubjectPublicKeyInfo`` is the 6th field
    (or the 7th when the optional explicit ``version`` field is present).
    """
    tag, value_start, value_end = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")
    outer = list(_iter_tlvs(der[value_start:value_end]))
    if len(outer) != 3:
        raise ValueError("unexpected certificate structure")
    _, tbs_value, tbs_len = outer[0]
    _, sig_alg_value, _ = outer[1]
    _, sig_value, _ = outer[2]

    tbs_fields = list(_iter_tlvs(tbs_value))
    offset = 1 if tbs_fields and tbs_fields[0][0] == 0xA0 else 0
    spki = tbs_fields[offset + 5]

    sig_alg_oid = _algorithm_oid(sig_alg_value)
    spki_oid = _spki_algorithm_oid(spki[1])

    return CertificateSizes(
        der_size=len(der),
        tbs_size=tbs_len,
        spki_size=spki[2],
        signature_size=len(sig_value) - 1,  # drop the unused-bits count byte
        signature_algorithm=_SIGNATURE_ALGORITHMS.get(sig_alg_oid, sig_alg_oid),
        public_key_algorithm=_PUBLIC_KEY_ALGORITHMS.get(spki_oid, spki_oid),
    )
