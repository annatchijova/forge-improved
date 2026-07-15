"""Tamper-evident hash chains for verification findings."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from forge.canonical import CANONICALIZE_VERSION, canonical_json
from forge.models import VerificationManifest

GENESIS_HASH = hashlib.sha256(b"FORGE-FINDINGS-GENESIS-v1").hexdigest()


def _digest(payload: Any, previous: str) -> str:
    return hashlib.sha256((canonical_json(payload) + previous).encode("utf-8")).hexdigest()


def seal_manifest(manifest: VerificationManifest) -> dict[str, Any]:
    data = manifest.to_dict()
    findings = data.pop("findings")
    chain = []
    previous = GENESIS_HASH
    for index, finding in enumerate(findings):
        entry = {"index": index, "prev_hash": previous, "finding": finding}
        entry["hash"] = _digest({"index": index, "finding": finding}, previous)
        chain.append(entry)
        previous = entry["hash"]
    return {
        "seal_version": "1",
        "canonicalize_version": CANONICALIZE_VERSION,
        "manifest": data,
        "reported_chain_length": len(chain),
        "chain": chain,
        "limitations": [
            "The seal proves findings were not altered after sealing.",
            "The seal does not prove findings are correct.",
            "A full-access attacker can forge a consistent replacement chain from scratch.",
        ],
    }


def verify_sealed(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("canonicalize_version") != CANONICALIZE_VERSION:
        return {"ok": False, "linkage_ok": False, "integrity_ok": False, "issues": ["unsupported canonicalize_version"]}
    linkage_ok = True
    integrity_ok = True
    issues: list[str] = []
    chain = data.get("chain", [])
    # This is informational only: an attacker can edit it after truncating.
    if data.get("reported_chain_length") != len(chain):
        linkage_ok = False
        issues.append("reported chain length mismatch")
    previous = GENESIS_HASH
    for expected_index, entry in enumerate(chain):
        index = entry.get("index")
        if index != expected_index:
            linkage_ok = False
            issues.append(f"entry {expected_index}: index/linkage mismatch")
        if entry.get("prev_hash") != previous:
            linkage_ok = False
            issues.append(f"entry {expected_index}: broken prev_hash linkage")
        actual = _digest({"index": index, "finding": entry.get("finding")}, entry.get("prev_hash", ""))
        if entry.get("hash") != actual:
            integrity_ok = False
            issues.append(f"entry {expected_index}: hash mismatch")
        previous = entry.get("hash", "")
    return {"ok": linkage_ok and integrity_ok, "linkage_ok": linkage_ok, "integrity_ok": integrity_ok, "issues": issues}


def write_sealed_manifest(manifest: VerificationManifest, destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(seal_manifest(manifest), sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read_and_verify(destination: str | Path) -> dict[str, Any]:
    return verify_sealed(json.loads(Path(destination).read_text(encoding="utf-8")))
