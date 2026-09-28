"""The three MTC workshop commands: ``lab``, ``shapes``, and ``verify``.

They are separate commands that share state on disk because that is how the
exercises are run: ``mtc lab`` builds the CA's log once, ``mtc shapes`` cuts
certificates from it, and ``mtc verify`` asks what a client with a given amount
of knowledge can check. Run them in that order.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Dict, Optional

from ..mtc import certs as mtc_certs
from ..mtc import client as mtc_client
from ..mtc import scenario as mtc_scenario
from ..mtc.scenario import Scenario

#: The knowledge a client can have, cheapest first. Each level is a superset of
#: the one before it, so the table from ``mtc verify`` reads as a staircase.
KNOWLEDGE = ("none", "cosigners", "landmark", "all")

SHAPE_LABELS = {
    "direct": "directly signed",
    "standalone": "standalone (tree-relative)",
    "checkpoint": "checkpoint-relative",
    "landmark": "landmark-relative",
}


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _state_for(scenario: Scenario, knows: str) -> mtc_client.ClientState:
    """Build a client that knows exactly what ``knows`` says it knows.

    Section 7.3 makes the relying party choose its cosigners, so "knows the
    cosigner keys" is the normal state and "holds a landmark" is what upgrades
    it. "none" is a client that trusts only the CA's ordinary signing key, which
    is the pre-MTC world.
    """
    state = mtc_client.ClientState()
    if knows in ("cosigners", "landmark", "all"):
        for cosigner in scenario.cosigners:
            state.add_cosigner(cosigner)
    if knows in ("landmark", "all"):
        state.take_landmarks(scenario.sequence, scenario.log.leaf_hashes())
    if knows == "all":
        # The CA's ordinary signing key is what checks the directly signed
        # shape, and nothing else. A client that trusts the cosigners and holds
        # a landmark can verify all three MTC shapes without it -- which is the
        # whole argument for having cosigners at all.
        state.add_ca_key(
            scenario.signer.ca_id,
            scenario.signer.parameter_set,
            scenario.signer.public_bytes(),
        )
    return state


def _checkpoint_size_for(scenario: Scenario, index: int, explicit: Optional[int]) -> int:
    """Choose which checkpoint the checkpoint-relative shape is measured against.

    Section 6.3 has the CA run the job when it checkpoints, and sign the
    subtrees covering the entries added since the *previous* checkpoint. The
    certificate for an entry is therefore built against the oldest checkpoint
    that already contains it -- for index 3 in this scenario, the size-12
    checkpoint. Picking the newest instead would measure against the whole log
    and collapse the checkpoint-relative row into a copy of the landmark one.
    """
    if explicit is not None:
        return explicit
    containing = [size for size in mtc_scenario.CHECKPOINT_SIZES if size > index]
    return min(containing) if containing else scenario.log.size


def _cert_summary(scenario: Scenario, index: int, checkpoint_size: int) -> Dict[str, object]:
    return mtc_certs.issue_all_four(
        scenario.log,
        index,
        scenario.spki(index),
        mtc_scenario.SUBJECT_ALGORITHM,
        scenario.cosigners,
        scenario.signer,
        scenario.landmark,
        checkpoint_size=checkpoint_size,
    )


def cmd_lab(args: argparse.Namespace) -> int:
    """Build the CA's log, its checkpoints, and its landmark, and save them."""
    if args.entries < 1:
        return _fail("--entries must be positive")
    scenario = mtc_scenario.build(entries=args.entries, log_number=args.log)
    for line in scenario.describe():
        print(line)
    print()
    print("cosigners")
    for cosigner in scenario.cosigners:
        print(f"  {cosigner.cosigner_id.dotted:<28} {cosigner.role} ({cosigner.parameter_set})")
    print(f"  {'(CA signing key)':<28} {scenario.signer.parameter_set}")
    print()
    print("public keys a client needs, and nothing else")
    print("  the cosigner public keys above, and the CA's key for the")
    print("  directly signed shape -- never the subject key, which stays in the certificate")
    path = mtc_scenario.save(scenario, args.outdir)
    print()
    print(f"saved {path}")
    return 0


def cmd_shapes(args: argparse.Namespace) -> int:
    """Cut the four certificate shapes from one entry and measure them."""
    scenario = mtc_scenario.load(args.outdir)
    index = args.index
    if not 0 <= index < scenario.log.size:
        return _fail(f"index {index} outside the log of {scenario.log.size} entries")
    if scenario.log.entries[index].tbs_certificate is None:
        return _fail(f"entry {index} is a null entry and cannot be certified")

    checkpoint_size = _checkpoint_size_for(scenario, index, args.checkpoint)
    if checkpoint_size <= index:
        return _fail(f"index {index} is not inside a checkpoint of size {checkpoint_size}")

    issued = _cert_summary(scenario, index, checkpoint_size)
    rows = mtc_certs.shape_sizes(
        scenario.log,
        index,
        scenario.spki(index),
        mtc_scenario.SUBJECT_ALGORITHM,
        scenario.cosigners,
        scenario.signer,
        scenario.landmark,
        checkpoint_size=checkpoint_size,
    )
    print(f"entry {index} of log {scenario.log.log_id.dotted}, serial "
          f"{scenario.log.serial(index)}")
    print(f"checkpoint-relative shape measured against the checkpoint of size "
          f"{checkpoint_size}")
    print()
    print(mtc_certs.format_shape_table(rows))
    print()
    print("one entry, four certificates, and the arithmetic behind the table")
    for name, cert in issued.items():
        row = next(r for r in rows if r["shape"] == SHAPE_LABELS[name])
        overhead = row["bytes"] - row["signature_bytes"] - row["proof_bytes"]
        print(f"  {SHAPE_LABELS[name]:<28} {row['bytes']:>5} bytes = "
              f"{row['signature_bytes']:>4} signature + {row['proof_bytes']:>4} proof + "
              f"{overhead:>4} fields")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, cert in issued.items():
        path = outdir / f"certificate-{name}.json"
        path.write_text(
            json.dumps(
                {
                    "shape": SHAPE_LABELS[name],
                    "index": index,
                    "serial": scenario.log.serial(index),
                    "text": str(cert),
                    "bytes": len(cert.encoded()),
                },
                indent=2,
            )
            + "\n"
        )
        written[name] = path.name
    print()
    print(f"wrote {', '.join(written[name] for name in issued)} to {outdir}")
    return 0


def _tamper(cert):
    """Break one field of a certificate, the way a hostile CA would.

    The subjectAltName is the most instructive field to change: it is in the
    entry, the entry is hashed into a subtree, and the subtree is what the
    cosigners signed or the landmark published, so every shape collapses at
    once.
    """
    return dataclasses.replace(cert, subject_alt_names=("evil.example",)), "subjectAltName"


def cmd_verify(args: argparse.Namespace) -> int:
    """Ask what a client with a given amount of knowledge can verify."""
    scenario = mtc_scenario.load(args.outdir)
    index = args.index
    if not 0 <= index < scenario.log.size:
        return _fail(f"index {index} outside the log of {scenario.log.size} entries")
    if scenario.log.entries[index].tbs_certificate is None:
        return _fail(f"entry {index} is a null entry and cannot be certified")
    if args.knows not in KNOWLEDGE:
        return _fail(f"--knows must be one of {', '.join(KNOWLEDGE)}")

    checkpoint_size = _checkpoint_size_for(scenario, index, args.checkpoint)
    issued = _cert_summary(scenario, index, checkpoint_size)
    state = _state_for(scenario, args.knows)

    print(f"client knowledge: {args.knows}")
    print(f"  {state}")
    if args.knows in ("landmark", "all"):
        print("  holding these landmark subtree hashes:")
        for start, end, subtree_hash in state.landmarks and sorted(
            (start, end, value) for (_, start, end), value in state.landmarks.items()
        ):
            print(f"    [{start}, {end}) -> {subtree_hash.hex()}")
    print()

    width = max(len(label) for label in SHAPE_LABELS.values())
    failures = 0
    for name, cert in issued.items():
        label = SHAPE_LABELS[name]
        checker = (
            mtc_client.verify_direct
            if isinstance(cert, mtc_certs.DirectCertificate)
            else mtc_client.verify
        )
        result = checker(cert, state)
        status = "verified" if result.ok else "refused"
        # On success the interesting part is *which* check carried it: the
        # cosignatures, or the landmark hash the client already had.
        line = result.detail if not result.ok else result.step
        if args.tamper:
            broken, field = _tamper(cert)
            tampered = checker(broken, state)
            print(
                f"{label:<{width}}  {status}   |  with {field} changed: "
                f"{'still verified' if tampered.ok else 'refused'}"
            )
            print(f"{'':<{width}}    {line}")
            if tampered.ok:
                failures += 1
            continue
        print(f"{label:<{width}}  {status}")
        print(f"{'':<{width}}    {line}")
    print()
    if args.tamper:
        if failures:
            print(f"FAIL: {failures} tampered certificate(s) were accepted")
            return 1
        print("every tampered certificate was refused")
        return 0
    return 0


def build_parser(sub) -> argparse.ArgumentParser:
    mtc = sub.add_parser(
        "mtc", help="Merkle Tree Certificate workshop lab (draft Sections 5-7)"
    )
    commands = mtc.add_subparsers(dest="mtc_command", required=True)

    lab = commands.add_parser(
        "lab", help="build the issuance log, checkpoints, and landmark"
    )
    lab.add_argument("--outdir", default="out/mtc", help="where to save the scenario")
    lab.add_argument("--entries", type=int, default=mtc_scenario.ENTRIES)
    lab.add_argument("--log", type=int, default=mtc_scenario.LOG_NUMBER, help="log number")
    lab.set_defaults(func=cmd_lab)

    shapes = commands.add_parser(
        "shapes", help="cut the four certificate shapes and size them"
    )
    shapes.add_argument("--outdir", default="out/mtc")
    shapes.add_argument("--index", type=int, default=mtc_scenario.CERT_INDEX)
    shapes.add_argument(
        "--checkpoint",
        type=int,
        help="tree size of the checkpoint the checkpoint-relative shape uses",
    )
    shapes.set_defaults(func=cmd_shapes)

    verify = commands.add_parser(
        "verify", help="run the relying-party walk for a client with some knowledge"
    )
    verify.add_argument("--outdir", default="out/mtc")
    verify.add_argument("--index", type=int, default=mtc_scenario.CERT_INDEX)
    verify.add_argument(
        "--knows",
        default="landmark",
        choices=KNOWLEDGE,
        help="what the client knows: cosigner keys, and/or landmark subtree hashes",
    )
    verify.add_argument(
        "--checkpoint", type=int, help="tree size of the checkpoint the shapes use"
    )
    verify.add_argument(
        "--tamper", action="store_true", help="also check that a changed field is refused"
    )
    verify.set_defaults(func=cmd_verify)
    return mtc
