"""Command-line interface: ``python3 -m lab.cli <command>``."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

from .. import bundle as bundle_mod
from .. import certs, measure, merkle, note, pki, staticct


def _hex(data: bytes) -> str:
    return data.hex()


def cmd_submit(args: argparse.Namespace) -> int:
    chain = []
    for path in args.chain:
        chain.extend(certs.read_certificates(path))
    if not chain:
        print("no certificates found", file=sys.stderr)
        return 1
    client = staticct.StaticCTClient(args.log, args.storage_dir)
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


def _read_key_arg(value: str) -> str:
    """Accept either a literal key or a path to a file containing one."""
    path = Path(value)
    if path.exists() and path.is_file():
        return path.read_text().strip()
    return value.strip()


def cmd_checkpoint(args: argparse.Namespace) -> int:
    if args.file:
        checkpoint = note.read_checkpoint(args.file)
    else:
        client = staticct.StaticCTClient(args.log or "", args.storage_dir)
        checkpoint = note.parse_checkpoint(client.checkpoint_bytes())
    print(f"origin      : {checkpoint.origin}")
    print(f"tree size   : {checkpoint.size}")
    print(f"root hash   : {_hex(checkpoint.root_hash)}")
    print(f"signatures  : {len(checkpoint.signatures)}")
    for signature in checkpoint.signatures:
        print(f"  - {signature.name} (keyhash {signature.key_hash:08x})")
    ok = True
    if args.pubkey:
        public_key = note.load_public_key(args.pubkey)
        sig_ok = note.verify_checkpoint(checkpoint, public_key)
        print(f"log signature  : {'VALID' if sig_ok else 'INVALID'}")
        ok = ok and sig_ok
    if args.witness_vkey:
        vkey = _read_key_arg(args.witness_vkey)
        witness_ok = note.verify_cosignature(checkpoint, vkey)
        name, _, _ = note.parse_vkey(vkey)
        print(f"witness cosig  : {'VALID' if witness_ok else 'INVALID'} ({name})")
        ok = ok and witness_ok
    return 0 if ok else 1


def cmd_proof(args: argparse.Namespace) -> int:
    client = staticct.StaticCTClient(args.log or "", args.storage_dir)
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
        client = staticct.StaticCTClient(args.log or "", args.storage_dir)
        entries = client.entries()
        proof = client.inclusion_proof(args.index)
        data = {
            "leaf_hash": _hex(entries[args.index].leaf_hash()),
            "leaf_index": args.index,
            "tree_size": len(entries),
            "audit_path": [_hex(node) for node in proof],
        }

    client = staticct.StaticCTClient(args.log or "", args.storage_dir)
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

    client = staticct.StaticCTClient(args.log, args.storage_dir)
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
    client = staticct.StaticCTClient(args.log or "", args.storage_dir)
    entries = client.entries()
    if not 0 <= args.index < len(entries):
        print(f"index {args.index} out of range (log has {len(entries)} entries)", file=sys.stderr)
        return 1
    entry = entries[args.index]
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


def cmd_bundle(args: argparse.Namespace) -> int:
    client = staticct.StaticCTClient(args.log or "", args.storage_dir)
    entries = client.entries()
    if not 0 <= args.index < len(entries):
        print(f"index {args.index} out of range (log has {len(entries)} entries)", file=sys.stderr)
        return 1
    entry = entries[args.index]
    checkpoint_raw = client.checkpoint_bytes()
    checkpoint = note.parse_checkpoint(checkpoint_raw)
    proof = client.inclusion_proof(args.index)

    bundle = bundle_mod.build_bundle(
        certificate=entry.certificate,
        leaf_index=args.index,
        tree_size=len(entries),
        leaf_hash=entry.leaf_hash(),
        audit_path=proof,
        checkpoint=checkpoint,
        checkpoint_raw=checkpoint_raw,
    )
    size = bundle_mod.write_bundle(bundle, args.output)

    if args.chain:
        chain_certs = certs.read_certificates(args.chain)
    else:
        pki_dir = Path(args.pki_dir) / args.algorithm
        chain_certs = certs.read_certificates(str(pki_dir / "leaf.crt")) + certs.read_certificates(
            str(pki_dir / "int.crt")
        )
    conventional = b"".join(chain_certs)
    leaf_certificate = chain_certs[0] if chain_certs else entry.certificate

    print(bundle_mod.format_comparison(bundle, leaf_certificate, conventional))
    print(f"\nWrote {args.output} ({size} bytes)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab.cli", description="Merkle Tree Lab client")
    sub = parser.add_subparsers(dest="command", required=True)

    submit = sub.add_parser("submit", help="submit a certificate chain to the log")
    submit.add_argument("--log", default="http://127.0.0.1:6962", help="log base URL")
    submit.add_argument("--storage-dir", default="log", help="log storage directory")
    submit.add_argument("--chain", nargs="+", required=True, help="PEM/DER certificate files")
    submit.set_defaults(func=cmd_submit)

    checkpoint = sub.add_parser("checkpoint", help="read and print the signed checkpoint")
    checkpoint.add_argument("--log", default="http://127.0.0.1:6962")
    checkpoint.add_argument("--storage-dir", default="log")
    checkpoint.add_argument("--file", help="read the checkpoint from this file instead")
    checkpoint.add_argument("--pubkey", help="verify the log signature with this PEM key")
    checkpoint.add_argument(
        "--witness-vkey", help="verify a witness cosignature with this note vkey (or a file)"
    )
    checkpoint.set_defaults(func=cmd_checkpoint)

    proof = sub.add_parser("proof", help="produce an inclusion proof for a leaf index")
    proof.add_argument("--storage-dir", default="log")
    proof.add_argument("--log", default="http://127.0.0.1:6962")
    proof.add_argument("--index", type=int, required=True)
    proof.add_argument("--output", help="write the proof JSON to this file")
    proof.set_defaults(func=cmd_proof)

    verify = sub.add_parser("verify", help="verify an inclusion proof against the checkpoint")
    verify.add_argument("--storage-dir", default="log")
    verify.add_argument("--log", default="http://127.0.0.1:6962")
    verify.add_argument("--index", type=int, default=0)
    verify.add_argument("--proof", help="proof JSON file (default: recompute)")
    verify.add_argument("--pubkey", help="also verify the checkpoint signature")
    verify.set_defaults(func=cmd_verify)

    walk = sub.add_parser("walk", help="print the inclusion proof hash-by-hash")
    walk.add_argument("--storage-dir", default="log")
    walk.add_argument("--log", default="http://127.0.0.1:6962")
    walk.add_argument("--index", type=int, required=True)
    walk.set_defaults(func=cmd_walk)

    pki_cmd = sub.add_parser("pki", help="generate a root/intermediate/leaf PKI")
    pki_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    pki_cmd.add_argument("--outdir", default="out/pki")
    pki_cmd.add_argument("--openssl", help="OpenSSL binary (default: $OPENSSL or 'openssl')")
    pki_cmd.add_argument("--force", action="store_true", help="regenerate even if present")
    pki_cmd.set_defaults(func=cmd_pki)

    measure_cmd = sub.add_parser("measure", help="measure certificate/signature sizes")
    measure_cmd.add_argument("--pki-dir", default="out/pki")
    measure_cmd.add_argument("--json", default="out/measurements.json")
    measure_cmd.add_argument("--markdown", default="out/measurements.md")
    measure_cmd.add_argument("--generate", action="store_true", help="generate missing PKIs first")
    measure_cmd.add_argument("--algorithms", nargs="+", choices=sorted(pki.ALGORITHMS))
    measure_cmd.add_argument("--openssl", help="OpenSSL binary (default: $OPENSSL or 'openssl')")
    measure_cmd.add_argument("--force", action="store_true", help="regenerate even if present")
    measure_cmd.set_defaults(func=cmd_measure)

    demo_cmd = sub.add_parser("demo", help="submit a cert and verify its inclusion proof")
    demo_cmd.add_argument("--log", default="http://127.0.0.1:6962")
    demo_cmd.add_argument("--storage-dir", default="log")
    demo_cmd.add_argument("--pki-dir", default="out/pki")
    demo_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    demo_cmd.add_argument("--log-key", default="out/log-key.pem", help="log signing key (PEM)")
    demo_cmd.add_argument("--openssl", help="OpenSSL binary")
    demo_cmd.add_argument("--timeout", type=float, default=30.0)
    demo_cmd.set_defaults(func=cmd_demo)

    bundle_cmd = sub.add_parser("bundle", help="build an MTC-shaped bundle and size it")
    bundle_cmd.add_argument("--storage-dir", default="log")
    bundle_cmd.add_argument("--log", default="http://127.0.0.1:6962")
    bundle_cmd.add_argument("--index", type=int, default=0)
    bundle_cmd.add_argument("--output", default="out/mtc_bundle.json")
    bundle_cmd.add_argument("--pki-dir", default="out/pki")
    bundle_cmd.add_argument("--algorithm", default="mldsa65", choices=sorted(pki.ALGORITHMS))
    bundle_cmd.add_argument("--chain", help="conventional chain PEM file(s) for comparison")
    bundle_cmd.set_defaults(func=cmd_bundle)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
