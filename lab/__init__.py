"""Merkle Tree Lab — Python client and tooling.

This package talks to a local TesseraCT POSIX log using the static-ct-api
submission endpoints and the tlog-tiles storage layout, and implements the
RFC 6962 Merkle hashing needed to verify inclusion proofs.

See IMPL.md (workstream WS2) for a guided explanation.
"""

__all__ = ["merkle", "certs", "note", "staticct"]
