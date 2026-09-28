"""Command-line interface: ``python3 -m lab.cli <command>``."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

from .. import certs, measure, merkle, note, pki, staticct


def _hex(data: bytes) -> str:
    return data.hex()


def _print_chain(chain: list[bytes]) -> None:
    """Verbose summary of the chain that will be POSTed to the log."""
    total = sum(len(der) for der in chain)
    print(f"chain: {len(chain)} certificate(s), {total} bytes DER total")
    for i, der in enumerate(chain):
        role = "leaf" if i == 0 else "issuer"
        b64_len = len(base64.b64encode(der))
        print(f"  [{i}] {role:<6} {len(der)} bytes DER -> {b64_len} base64 chars")


def _print_entry(entry: staticct.Entry) -> None:
    """Verbose description of a logged entry and its MerkleTreeLeaf."""
    kind = "precert" if entry.is_precert else "x509"
    print(
        f"entry {entry.leaf_index}: type={kind} timestamp={entry.timestamp} "
        f"cert={len(entry.certificate)} bytes extensions={entry.extensions.hex()} "
        f"fingerprints={len(entry.fingerprints)} bytes"
    )
    leaf = entry.merkle_tree_leaf()
    entry_type = 1 if entry.is_precert else 0
    print(
        f"  MerkleTreeLeaf: {len(leaf)} bytes "
        f"(version=0, leaf_type=0, entry_type={entry_type}, "
        f"cert_len={len(entry.certificate)}, ext_len={len(entry.extensions)})"
    )


DEFAULT_ORIGIN = "example.com/workshop"


def _client(args: argparse.Namespace) -> staticct.StaticCTClient:
    """Build a CT client that knows the log's submission prefix.

    The origin is not decoration: a log checks that requests arrive on its
    submission prefix, so a client that ignores it earns a warning per request
    and, once the server is configured with --path_prefix, a 404.
    """
    return staticct.StaticCTClient(
        args.log or "",
        args.storage_dir,
        verbose=args.verbose,
        origin=getattr(args, "origin", None) or None,
    )


def cmd_submit(args: argparse.Namespace) -> int:
    chain = []
    for path in args.chain:
        chain.extend(certs.read_certificates(path))
    if not chain:
        print("no certificates found", file=sys.stderr)
        return 1
    if args.verbose:
        _print_chain(chain)
    client = _client(args)
    response = client.add_chain(chain)
    extensions = base64.b64decode(response.get("extensions", ""))
    try:
        leaf_index = staticct.parse_ct_extensions(extensions)
    except ValueError:
        leaf_index = None
    print(f"Submitted {len(chain)} certificate(s) to {args.log}")
    print(f"  SCT timestamp : {response.get('timestamp')}")
    print(f"  leaf index    : {leaf_index}")
    print(f"  log id        : {response.get('id')}")
    return 0


def cmd_fill(args: argparse.Namespace) -> int:
    """Submit several distinct certificates so the log's tree actually grows.

    ``cmd_demo`` submits the one leaf certificate in ``out/pki``, and re-running
    it submits the *same* certificate again. A CT log deduplicates entries by
    certificate, so the second submission is accepted and signed but integrates
    nothing: the tree stays at size 1 and the inclusion proof has no siblings.
    That is fine for demonstrating an SCT, useless for exercise 04, which needs
    a real tree to walk.

    So this issues ``--count`` fresh leaves from the same intermediate and
    submits each one. Distinct subject names mean distinct DER, distinct leaf
    hashes, and entries the log will actually integrate.
    """
    pki_dir = Path(args.pki_dir)
    if args.count < 1:
        print(f"--count must be at least 1, got {args.count}", file=sys.stderr)
        return 1
    directory = pki_dir / args.algorithm
    if not (directory / "int.crt").exists():
        pki.ensure_openssl(args.openssl)
        pki.generate(args.algorithm, pki_dir, openssl=args.openssl)

    client = _client(args)
    names = [f"www{index}" for index in range(args.count)]
    submitted = []
    for name in names:
        leaf = pki.issue_leaf(args.algorithm, pki_dir, name, openssl=args.openssl)
        chain = certs.read_certificates(str(leaf)) + certs.read_certificates(
            str(directory / "int.crt")
        )
        response = client.add_chain(chain)
        extensions = base64.b64decode(response.get("extensions", ""))
        try:
            index = staticct.parse_ct_extensions(extensions)
        except ValueError:
            index = None
        submitted.append(index)
        if args.verbose:
            print(f"  submitted {name}.example at index {index}")

    deadline = time.time() + args.timeout
    size = 0
    highest = max((i for i in submitted if i is not None), default=None)
    while time.time() < deadline:
        try:
            size = note.parse_checkpoint(client.checkpoint_bytes()).size
        except FileNotFoundError:
            size = 0
        if highest is not None and size > highest:
            break
        time.sleep(0.25)

    if highest is None:
        # Every submission came back without a usable SCT leaf index, so there is
        # nothing to wait for. Say that, rather than blaming the checkpoint.
        print(
            f"Filled the log with {len(names)} {args.algorithm} leaves, but none of them "
            f"returned a parseable SCT leaf index",
            file=sys.stderr,
        )
        return 1

    print(f"Filled the log with {len(names)} distinct {args.algorithm} leaves")
    print(f"  leaf indices  : {', '.join(str(i) for i in submitted)}")
    print(f"  tree size     : {size}")
    if size <= highest:
        print("  the log has not published a checkpoint covering them yet", file=sys.stderr)
        return 1
    # The newest leaf may still be a lone leaf; the oldest one is guaranteed to
    # have a sibling now that the tree holds more than one entry.
    oldest = min(i for i in submitted if i is not None)
    print(f"\nNow walk a proof that has siblings: lab.cli walk --index {oldest}")
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    if args.file:
        checkpoint = note.read_checkpoint(args.file)
    else:
        client = _client(args)
        checkpoint = note.parse_checkpoint(client.checkpoint_bytes())
    print(f"origin      : {checkpoint.origin}")
    print(f"tree size   : {checkpoint.size}")
    print(f"root hash   : {_hex(checkpoint.root_hash)}")
    print(f"signatures  : {len(checkpoint.signatures)}")
    for signature in checkpoint.signatures:
        print(f"  - {signature.name} (keyhash {signature.key_hash:08x})")
    if args.pubkey:
        public_key = note.load_public_key(args.pubkey)
        sig_ok = note.verify_checkpoint(checkpoint, public_key)
        print(f"log signature  : {'VALID' if sig_ok else 'INVALID'}")
        return 0 if sig_ok else 1
    return 0



def cmd_proof(args: argparse.Namespace) -> int:
    client = _client(args)
    entries = client.entries()
    if not 0 <= args.index < len(entries):
        print(f"index {args.index} out of range (log has {len(entries)} entries)", file=sys.stderr)
        return 1
    proof = client.inclusion_proof(args.index)
    output = {
        "leaf_hash": _hex(entries[args.index].leaf_hash()),
        "leaf_index": args.index,
        "tree_size": len(entries),
        "audit_path": [_hex(node) for node in proof],
    }
    text = json.dumps(output, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if args.proof:
        data = json.loads(Path(args.proof).read_text())
    else:
        client = _client(args)
        entries = client.entries()
        proof = client.inclusion_proof(args.index)
        data = {
            "leaf_hash": _hex(entries[args.index].leaf_hash()),
            "leaf_index": args.index,
            "tree_size": len(entries),
            "audit_path": [_hex(node) for node in proof],
        }

    client = _client(args)
    checkpoint = note.parse_checkpoint(client.checkpoint_bytes())

    leaf_hash = bytes.fromhex(data["leaf_hash"])
    audit_path = [bytes.fromhex(node) for node in data["audit_path"]]
    ok = merkle.verify_inclusion(
        leaf_hash=leaf_hash,
        index=data["leaf_index"],
        tree_size=data["tree_size"],
        proof=audit_path,
        root=checkpoint.root_hash,
    )
    print(f"inclusion proof : {'VALID' if ok else 'INVALID'}")
    print(f"  leaf index    : {data['leaf_index']}")
    print(f"  tree size     : {data['tree_size']}")
    print(f"  audit path    : {len(audit_path)} hash(es)")
    print(f"  checkpoint    : size={checkpoint.size} root={_hex(checkpoint.root_hash)}")

    if args.pubkey:
        public_key = note.load_public_key(args.pubkey)
        sig_ok = note.verify_checkpoint(checkpoint, public_key)
        print(f"  checkpoint sig: {'VALID' if sig_ok else 'INVALID'}")
        ok = ok and sig_ok
    return 0 if ok else 1


def cmd_pki(args: argparse.Namespace) -> int:
    pki.ensure_openssl(args.openssl)
    paths = pki.generate(
        args.algorithm, Path(args.outdir), openssl=args.openssl, force=args.force
    )
    print(f"Generated {paths.algorithm} PKI in {paths.directory}")
    print(f"  root : {paths.root_crt}")
    print(f"  int  : {paths.int_crt}")
    print(f"  leaf : {paths.leaf_crt}")
    return 0


def cmd_measure(args: argparse.Namespace) -> int:
    pki_dir = Path(args.pki_dir)
    if args.generate:
        pki.ensure_openssl(args.openssl)
        algorithms = args.algorithms or pki.DEFAULT_ALGORITHMS
        print(f"Generating {len(algorithms)} PKI(s) in {pki_dir} ...")
        pki.generate_all(algorithms, pki_dir, openssl=args.openssl, force=args.force)

    measurements = measure.measure_directory(pki_dir)
    if not measurements:
        print(f"no generated PKIs found in {pki_dir}", file=sys.stderr)
        return 1
    print(measure.format_markdown(measurements))
    measure.write_reports(measurements, Path(args.json), Path(args.markdown))
    print(f"Wrote {args.json} and {args.markdown}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    pki_dir = Path(args.pki_dir)
    leaf = pki_dir / args.algorithm / "leaf.crt"
    intermediate = pki_dir / args.algorithm / "int.crt"
    if not leaf.exists():
        pki.ensure_openssl(args.openssl)
        pki.generate(args.algorithm, pki_dir, openssl=args.openssl)
    chain = certs.read_certificates(str(leaf)) + certs.read_certificates(str(intermediate))
    leaf_der = chain[0]
    if args.verbose:
        _print_chain(chain)

    client = _client(args)
    response = client.add_chain(chain)
    extensions = base64.b64decode(response.get("extensions", ""))
    try:
        leaf_index = staticct.parse_ct_extensions(extensions)
    except ValueError:
        leaf_index = None
    print(f"Submitted {args.algorithm} leaf certificate")
    print(f"  SCT timestamp : {response.get('timestamp')}")
    print(f"  leaf index    : {leaf_index}")

    deadline = time.time() + args.timeout
    entry = None
    checkpoint = None
    while time.time() < deadline:
        entries = client.entries()
        entry = next((e for e in entries if e.certificate == leaf_der), None)
        try:
            checkpoint = note.parse_checkpoint(client.checkpoint_bytes())
        except FileNotFoundError:
            checkpoint = None
        if entry and checkpoint and checkpoint.size > entry.leaf_index:
            break
        time.sleep(0.25)

    if entry is None:
        print("submitted entry was not found in the log", file=sys.stderr)
        return 1
    if checkpoint is None:
        print("checkpoint was not published in time", file=sys.stderr)
        return 1

    proof = client.inclusion_proof(entry.leaf_index)
    inclusion_ok = merkle.verify_inclusion(
        entry.leaf_hash(), entry.leaf_index, checkpoint.size, proof, checkpoint.root_hash
    )
    print(f"Checkpoint    : size={checkpoint.size} root={checkpoint.root_hash.hex()}")
    print(f"Inclusion     : {'VALID' if inclusion_ok else 'INVALID'} ({len(proof)} audit hash(es))")

    signature_ok = None
    if args.log_key and Path(args.log_key).exists():
        public_key = note.load_public_key(args.log_key)
        signature_ok = note.verify_checkpoint(checkpoint, public_key)
        print(f"Checkpoint sig: {'VALID' if signature_ok else 'INVALID'}")

    return 0 if inclusion_ok and signature_ok is not False else 1


def cmd_walk(args: argparse.Namespace) -> int:
    client = _client(args)
    entries = client.entries()
    if not 0 <= args.index < len(entries):
        print(f"index {args.index} out of range (log has {len(entries)} entries)", file=sys.stderr)
        return 1
    entry = entries[args.index]
    if args.verbose:
        _print_entry(entry)
    proof = client.inclusion_proof(args.index)
    root, steps = merkle.explain_inclusion(entry.leaf_hash(), args.index, len(entries), proof)
    checkpoint = note.parse_checkpoint(client.checkpoint_bytes())

    print(f"leaf {args.index} in a tree of size {len(entries)}")
    print(f"  leaf hash : {entry.leaf_hash().hex()}")
    if not steps:
        print("  (single-leaf tree: the leaf hash is the root)")
    for step in steps:
        order = "H(cur || sib)" if step["side"] == "right" else "H(sib || cur)"
        print(
            f"  level {step['level']} [{step['kind']:>6}, sibling {step['side']:>5}] "
            f"{order} -> {step['after'].hex()}"
        )
    print(f"  computed root : {root.hex()}")
    print(f"  checkpoint    : {checkpoint.root_hash.hex()}")
    print(f"  MATCH         : {root == checkpoint.root_hash}")
    return 0 if root == checkpoint.root_hash else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab.cli", description="Merkle Tree Lab client")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v", "--verbose", action="store_true",
        help="trace HTTP requests and storage reads (shows how the chain is submitted)",
    )

    submit = sub.add_parser(
        "submit", parents=[common], help="submit a certificate chain to the log"
    )
    submit.add_argument("--log", default="http://127.0.0.1:6962", help="log base URL")
    submit.add_argument("--storage-dir", default="log", help="log storage directory")
    submit.add_argument("--chain", nargs="+", required=True, help="PEM/DER certificate files")
    submit.set_defaults(func=cmd_submit)

    checkpoint = sub.add_parser(
        "checkpoint", parents=[common], help="read and print the signed checkpoint"
    )
    checkpoint.add_argument("--log", default="http://127.0.0.1:6962")
    checkpoint.add_argument("--storage-dir", default="log")
    checkpoint.add_argument("--file", help="read the checkpoint from this file instead")
    checkpoint.add_argument("--pubkey", help="verify the log signature with this PEM key")
    checkpoint.set_defaults(func=cmd_checkpoint)

    proof = sub.add_parser(
        "proof", parents=[common], help="produce an inclusion proof for a leaf index"
    )
    proof.add_argument("--storage-dir", default="log")
    proof.add_argument("--log", default="http://127.0.0.1:6962")
    proof.add_argument("--index", type=int, required=True)
    proof.add_argument("--output", help="write the proof JSON to this file")
    proof.set_defaults(func=cmd_proof)

    verify = sub.add_parser(
        "verify", parents=[common], help="verify an inclusion proof against the checkpoint"
    )
    verify.add_argument("--storage-dir", default="log")
    verify.add_argument("--log", default="http://127.0.0.1:6962")
    verify.add_argument("--index", type=int, default=0)
    verify.add_argument("--proof", help="proof JSON file (default: recompute)")
    verify.add_argument("--pubkey", help="also verify the checkpoint signature")
    verify.set_defaults(func=cmd_verify)

    walk = sub.add_parser(
        "walk", parents=[common], help="print the inclusion proof hash-by-hash"
    )
    walk.add_argument("--storage-dir", default="log")
    walk.add_argument("--log", default="http://127.0.0.1:6962")
    walk.add_argument("--index", type=int, required=True)
    walk.set_defaults(func=cmd_walk)

    pki_cmd = sub.add_parser(
        "pki", parents=[common], help="generate a root/intermediate/leaf PKI"
    )
    pki_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    pki_cmd.add_argument("--outdir", default="out/pki")
    pki_cmd.add_argument("--openssl", help="OpenSSL binary (default: $OPENSSL or 'openssl')")
    pki_cmd.add_argument("--force", action="store_true", help="regenerate even if present")
    pki_cmd.set_defaults(func=cmd_pki)

    measure_cmd = sub.add_parser(
        "measure", parents=[common], help="measure certificate/signature sizes"
    )
    measure_cmd.add_argument("--pki-dir", default="out/pki")
    measure_cmd.add_argument("--json", default="out/measurements.json")
    measure_cmd.add_argument("--markdown", default="out/measurements.md")
    measure_cmd.add_argument("--generate", action="store_true", help="generate missing PKIs first")
    measure_cmd.add_argument("--algorithms", nargs="+", choices=sorted(pki.ALGORITHMS))
    measure_cmd.add_argument("--openssl", help="OpenSSL binary (default: $OPENSSL or 'openssl')")
    measure_cmd.add_argument("--force", action="store_true", help="regenerate even if present")
    measure_cmd.set_defaults(func=cmd_measure)

    demo_cmd = sub.add_parser(
        "demo", parents=[common], help="submit a cert and verify its inclusion proof"
    )
    demo_cmd.add_argument("--log", default="http://127.0.0.1:6962")
    demo_cmd.add_argument("--storage-dir", default="log")
    demo_cmd.add_argument("--pki-dir", default="out/pki")
    demo_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    demo_cmd.add_argument("--log-key", default="out/log-key.pem", help="log signing key (PEM)")
    demo_cmd.add_argument("--openssl", help="OpenSSL binary")
    demo_cmd.add_argument("--timeout", type=float, default=30.0)
    demo_cmd.set_defaults(func=cmd_demo)

    fill_cmd = sub.add_parser(
        "fill",
        parents=[common],
        help="submit several *distinct* certificates, so the log's tree grows",
    )
    fill_cmd.add_argument("--count", type=int, default=8, help="how many leaves to add")
    fill_cmd.add_argument("--log", default="http://127.0.0.1:6962")
    fill_cmd.add_argument("--storage-dir", default="log")
    fill_cmd.add_argument("--pki-dir", default="out/pki")
    fill_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    fill_cmd.add_argument("--openssl", help="OpenSSL binary")
    fill_cmd.add_argument("--timeout", type=float, default=30.0)
    fill_cmd.set_defaults(func=cmd_fill)

    from .mtc import build_parser as build_mtc_parser

    build_mtc_parser(sub)

    # The log's origin is its submission prefix, so every command that talks to
    # a log over HTTP needs it. Defaults match scripts/run_tesseract.sh so that
    # "make lab-up" and "make demo" agree without anyone passing anything.
    for action in sub.choices.values():
        if any("--log" in str(a.option_strings) for a in action._actions):
            action.add_argument(
                "--origin", default=DEFAULT_ORIGIN,
                help="log origin, i.e. its submission prefix (default %(default)s)",
            )

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
