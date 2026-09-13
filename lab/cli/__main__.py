"""Command-line interface: ``python3 -m lab.cli <command>``."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from .. import certs, merkle, note, staticct


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
    if args.pubkey:
        public_key = note.load_public_key(args.pubkey)
        ok = note.verify_checkpoint(checkpoint, public_key)
        print(f"signature   : {'VALID' if ok else 'INVALID'}")
        return 0 if ok else 1
    return 0


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
    checkpoint.add_argument("--pubkey", help="verify the signature with this PEM key")
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

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
