"""Generate classical and post-quantum certificate chains with OpenSSL.

Every algorithm produces the same three-tier hierarchy::

    root CA  ->  intermediate CA  ->  leaf (server) certificate

The point of the exercise is to hold the *shape* of the PKI constant and vary
only the signature algorithm, so that measured size differences come from the
cryptography rather than from the certificate layout.

Two OpenSSL details matter:

* The intermediate must be signed with ``basicConstraints=CA:TRUE`` (see
  ``scripts/openssl/ca_ext.cnf``) or ``openssl verify`` rejects it.
* Post-quantum key types are requested simply with ``-newkey ML-DSA-65`` and
  friends; OpenSSL 3.5's default provider understands them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
OPENSSL_CA_EXT = REPO_ROOT / "scripts" / "openssl" / "ca_ext.cnf"
OPENSSL_LEAF_EXT = REPO_ROOT / "scripts" / "openssl" / "leaf_ext.cnf"


@dataclass(frozen=True)
class Algorithm:
    name: str
    label: str
    family: str
    key_args: List[str]


ALGORITHMS: Dict[str, Algorithm] = {
    "ecdsa-p256": Algorithm(
        "ecdsa-p256", "ECDSA P-256", "classical", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
    ),
    "rsa-2048": Algorithm("rsa-2048", "RSA-2048", "classical", ["rsa:2048"]),
    "ed25519": Algorithm("ed25519", "Ed25519", "classical", ["ed25519"]),
    "mldsa44": Algorithm("mldsa44", "ML-DSA-44", "pqc", ["ML-DSA-44"]),
    "mldsa65": Algorithm("mldsa65", "ML-DSA-65", "pqc", ["ML-DSA-65"]),
    "mldsa87": Algorithm("mldsa87", "ML-DSA-87", "pqc", ["ML-DSA-87"]),
    "slhdsa-sha2-128s": Algorithm(
        "slhdsa-sha2-128s", "SLH-DSA-SHA2-128s", "pqc", ["SLH-DSA-SHA2-128s"]
    ),
    "slhdsa-sha2-128f": Algorithm(
        "slhdsa-sha2-128f", "SLH-DSA-SHA2-128f", "pqc", ["SLH-DSA-SHA2-128f"]
    ),
    "slhdsa-shake-128s": Algorithm(
        "slhdsa-shake-128s", "SLH-DSA-SHAKE-128s", "pqc", ["SLH-DSA-SHAKE-128s"]
    ),
    "falcon512": Algorithm("falcon512", "Falcon-512", "pqc", ["falcon512"]),
    "falcon1024": Algorithm("falcon1024", "Falcon-1024", "pqc", ["falcon1024"]),
}

DEFAULT_ALGORITHMS = ["ecdsa-p256", "rsa-2048", "mldsa44", "mldsa65", "slhdsa-sha2-128s"]


@dataclass
class PkiPaths:
    algorithm: str
    directory: Path
    root_crt: Path
    root_key: Path
    int_crt: Path
    int_key: Path
    leaf_crt: Path
    leaf_key: Path

    def all_certificates(self) -> List[Path]:
        return [self.leaf_crt, self.int_crt, self.root_crt]


class PkiError(RuntimeError):
    pass


def openssl_binary() -> str:
    """Return the OpenSSL binary to use (``OPENSSL`` env var or ``openssl``)."""
    return os.environ.get("OPENSSL", "openssl")


def _run(args: List[str], cwd: Path) -> None:
    try:
        subprocess.run(args, cwd=cwd, check=True, capture_output=True)
    except FileNotFoundError as exc:
        raise PkiError(f"could not run {args[0]}: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode(errors="replace").strip()
        raise PkiError(f"command failed: {' '.join(args)}\n{message}") from exc


def generate(
    algorithm: str,
    outdir: Path,
    openssl: Optional[str] = None,
    root_days: int = 3650,
    int_days: int = 1825,
    leaf_days: int = 365,
    force: bool = False,
) -> PkiPaths:
    """Generate a root/intermediate/leaf chain for one algorithm."""
    if algorithm not in ALGORITHMS:
        raise PkiError(f"unknown algorithm {algorithm!r}; known: {', '.join(sorted(ALGORITHMS))}")
    alg = ALGORITHMS[algorithm]
    openssl = openssl or openssl_binary()
    directory = Path(outdir) / algorithm

    paths = PkiPaths(
        algorithm=algorithm,
        directory=directory,
        root_crt=directory / "root.crt",
        root_key=directory / "root.key",
        int_crt=directory / "int.crt",
        int_key=directory / "int.key",
        leaf_crt=directory / "leaf.crt",
        leaf_key=directory / "leaf.key",
    )
    if paths.leaf_crt.exists() and not force:
        return paths

    directory.mkdir(parents=True, exist_ok=True)

    # Root CA (self-signed).
    _run(
        [
            openssl, "req", "-x509", "-newkey", *alg.key_args,
            "-keyout", "root.key", "-out", "root.crt",
            "-days", str(root_days), "-nodes",
            "-subj", f"/CN={alg.label} Root",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        directory,
    )

    # Intermediate CA.
    _run(
        [
            openssl, "req", "-new", "-newkey", *alg.key_args,
            "-keyout", "int.key", "-out", "int.csr", "-nodes",
            "-subj", f"/CN={alg.label} Intermediate",
        ],
        directory,
    )
    _run(
        [
            openssl, "x509", "-req", "-in", "int.csr",
            "-CA", "root.crt", "-CAkey", "root.key", "-CAcreateserial",
            "-out", "int.crt", "-days", str(int_days),
            "-extfile", str(OPENSSL_CA_EXT), "-extensions", "v3_ca",
        ],
        directory,
    )

    # Leaf certificate.
    _run(
        [
            openssl, "req", "-new", "-newkey", *alg.key_args,
            "-keyout", "leaf.key", "-out", "leaf.csr", "-nodes",
            "-subj", f"/CN=leaf.example ({alg.label})",
        ],
        directory,
    )
    _run(
        [
            openssl, "x509", "-req", "-in", "leaf.csr",
            "-CA", "int.crt", "-CAkey", "int.key", "-CAcreateserial",
            "-out", "leaf.crt", "-days", str(leaf_days),
            "-extfile", str(OPENSSL_LEAF_EXT), "-extensions", "v3_leaf",
        ],
        directory,
    )

    # Sanity check the chain.
    _run(
        [openssl, "verify", "-CAfile", "root.crt", "-untrusted", "int.crt", "leaf.crt"],
        directory,
    )
    return paths


def issue_leaf(
    algorithm: str,
    outdir: Path,
    name: str,
    openssl: Optional[str] = None,
    days: int = 365,
) -> Path:
    """Issue one extra leaf from an *existing* intermediate, and return its path.

    :func:`generate` makes one leaf per algorithm, and re-running it returns the
    same certificate. That is right for measuring sizes but useless for building
    a CT tree: the log deduplicates entries by certificate, so submitting the
    same leaf twice integrates it once and the tree never grows past one entry.

    This issues a genuinely distinct certificate under the same intermediate --
    a fresh key and a different subject name, so the DER differs and the leaf
    hash differs. The root and intermediate are untouched, so certificates
    issued before and after are interchangeable for a client that trusts the
    root.
    """
    if algorithm not in ALGORITHMS:
        raise PkiError(
            f"unknown algorithm {algorithm!r}; known: {', '.join(sorted(ALGORITHMS))}"
        )
    alg = ALGORITHMS[algorithm]
    openssl = openssl or openssl_binary()
    # _run() executes with cwd=directory, so every path handed to OpenSSL has to
    # be absolute or it will be resolved against the wrong directory.
    directory = (Path(outdir) / algorithm).resolve()
    int_crt = directory / "int.crt"
    int_key = directory / "int.key"
    if not (int_crt.exists() and int_key.exists()):
        raise PkiError(
            f"no intermediate at {int_crt}; run 'lab.cli pki --algorithm {algorithm}' first"
        )

    directory.mkdir(parents=True, exist_ok=True)
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    crt = directory / f"{name}.crt"

    _run(
        [
            openssl, "req", "-new", "-newkey", *alg.key_args,
            "-keyout", str(key), "-out", str(csr), "-nodes",
            "-subj", f"/CN={name}.example",
        ],
        directory,
    )
    _run(
        [
            openssl, "x509", "-req", "-in", str(csr),
            "-CA", str(int_crt), "-CAkey", str(int_key), "-CAcreateserial",
            "-out", str(crt), "-days", str(days),
            "-extfile", str(OPENSSL_LEAF_EXT), "-extensions", "v3_leaf",
        ],
        directory,
    )
    _run(
        [
            openssl, "verify",
            "-CAfile", str(directory / "root.crt"),
            "-untrusted", str(int_crt), str(crt),
        ],
        directory,
    )
    return crt


def generate_all(
    algorithms: Iterable[str],
    outdir: Path,
    openssl: Optional[str] = None,
    **kwargs,
) -> Dict[str, PkiPaths]:
    """Generate several chains, skipping algorithms OpenSSL does not support."""
    results: Dict[str, PkiPaths] = {}
    for name in algorithms:
        try:
            results[name] = generate(name, outdir, openssl=openssl, **kwargs)
        except PkiError as exc:
            print(f"  skip {name}: {exc}")
    return results


def ensure_openssl(openssl: Optional[str] = None) -> None:
    """Fail early with a clear message if OpenSSL is missing."""
    binary = openssl or openssl_binary()
    if shutil.which(binary) is None and not Path(binary).exists():
        raise PkiError(f"OpenSSL binary not found: {binary}")
