"""Tamper-evident hash chains for verification findings."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from forge.canonical import CANONICALIZE_VERSION, canonical_json
from forge.attestation import attest_manifest, attestation_mode, verify_manifest_attestation
from forge.io import load_json
from forge.models import VerificationManifest

GENESIS_HASH = hashlib.sha256(b"FORGE-FINDINGS-GENESIS-v1").hexdigest()


def _digest(payload: Any, previous: str) -> str:
    return hashlib.sha256((canonical_json(payload) + previous).encode("utf-8")).hexdigest()


def _configured_authentication_key() -> bytes | None:
    """Read the optional out-of-band seal key without serializing it."""
    value = os.environ.get("FORGE_SEAL_HMAC_KEY")
    return value.encode("utf-8") if value else None


def _authentication_payload(sealed: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in sealed.items() if key != "authentication"}


def _authentication_tag(sealed: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_json(_authentication_payload(sealed)).encode("utf-8"), hashlib.sha256).hexdigest()


def seal_manifest(manifest: VerificationManifest, audit_trace: dict[str, Any] | None = None) -> dict[str, Any]:
    data = manifest.to_dict()
    findings = data.pop("findings")
    data["finding_set_digest"] = hashlib.sha256(canonical_json(findings).encode("utf-8")).hexdigest()
    return seal_findings(findings, data, audit_trace)


def seal_findings(findings: list[dict[str, Any]], metadata: dict[str, Any] | None = None, audit_trace: dict[str, Any] | None = None) -> dict[str, Any]:
    """Seal an already canonicalized finding list without changing its schema."""
    data = dict(metadata or {})
    trace_hash = hashlib.sha256(canonical_json(audit_trace).encode("utf-8")).hexdigest() if audit_trace is not None else ""
    if trace_hash: data["audit_trace_hash"] = trace_hash
    chain = []
    previous = GENESIS_HASH
    for index, finding in enumerate(findings):
        # The chain hash intentionally excludes trace_hash: run_id and
        # started_at inside audit_trace are run-specific (a fresh UUID and a
        # wall-clock timestamp each run), so folding them into the per-finding
        # hash would make two honest runs over identical findings produce
        # different chain hashes - a real bit-for-bit reproducibility break
        # (deterministic-core), for no security benefit, since audit_trace_hash
        # is already independently tamper-evident as top-level manifest
        # metadata (verified against the stored audit_trace below).
        entry = {"index": index, "prev_hash": previous, "finding": finding}
        payload = {"index": index, "finding": finding}
        entry["hash"] = _digest(payload, previous)
        chain.append(entry)
        previous = entry["hash"]
    sealed = {
        "seal_version": "1",
        "canonicalize_version": CANONICALIZE_VERSION,
        "manifest": data,
        "reported_chain_length": len(chain),
        "chain": chain,
        **({"audit_trace": audit_trace} if audit_trace is not None else {}),
        "limitations": [
            "The seal proves findings were not altered after sealing.",
            "The seal does not prove findings are correct.",
            "A full-access attacker can forge a consistent replacement chain from scratch.",
        ],
    }
    # This attests the assembly of this exact sealed artifact. It does not
    # attest the analytical provenance of every source layer inside it.
    sealed["source_attestation_mode"] = attestation_mode()
    sealed["source_attestation"] = attest_manifest(sealed)
    key = _configured_authentication_key()
    if key is not None:
        sealed["authentication"] = {"scheme": "HMAC-SHA256", "tag": _authentication_tag(sealed, key)}
    return sealed


def verify_sealed(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("canonicalize_version") != CANONICALIZE_VERSION:
        return {"ok": False, "linkage_ok": False, "integrity_ok": False, "issues": ["unsupported canonicalize_version"]}
    linkage_ok = True
    integrity_ok = True
    authentication_ok: bool | None = None
    authentication_status = "NOT_CONFIGURED"
    attestation_ok: bool | None = None
    attestation_status = "NOT_PRESENT"
    issues: list[str] = []
    chain = data.get("chain", [])
    # This is informational only: an attacker can edit it after truncating.
    if data.get("reported_chain_length") != len(chain):
        linkage_ok = False
        issues.append("reported chain length mismatch")
    previous = GENESIS_HASH
    trace_hash = data.get("manifest", {}).get("audit_trace_hash", "")
    if trace_hash:
        trace = data.get("audit_trace")
        if trace is None:
            integrity_ok = False; issues.append("audit trace missing")
        elif hashlib.sha256(canonical_json(trace).encode("utf-8")).hexdigest() != trace_hash:
            integrity_ok = False; issues.append("audit trace hash mismatch")
    for expected_index, entry in enumerate(chain):
        index = entry.get("index")
        if index != expected_index:
            linkage_ok = False
            issues.append(f"entry {expected_index}: index/linkage mismatch")
        if entry.get("prev_hash") != previous:
            linkage_ok = False
            issues.append(f"entry {expected_index}: broken prev_hash linkage")
        payload = {"index": index, "finding": entry.get("finding")}
        actual = _digest(payload, entry.get("prev_hash", ""))
        if entry.get("hash") != actual:
            integrity_ok = False
            issues.append(f"entry {expected_index}: hash mismatch")
        previous = entry.get("hash", "")
    authentication = data.get("authentication")
    if authentication is not None:
        if not isinstance(authentication, dict) or authentication.get("scheme") != "HMAC-SHA256":
            authentication_ok = False
            authentication_status = "UNSUPPORTED"
            issues.append("unsupported authentication scheme")
        else:
            key = _configured_authentication_key()
            if key is None:
                authentication_ok = False
                authentication_status = "KEY_UNAVAILABLE"
                issues.append("authentication key unavailable")
            else:
                authentication_ok = hmac.compare_digest(str(authentication.get("tag", "")), _authentication_tag(data, key))
                authentication_status = "VERIFIED" if authentication_ok else "FAILED"
                if not authentication_ok:
                    issues.append("authentication tag mismatch")
    source_attestation = data.get("source_attestation")
    source_mode = data.get("source_attestation_mode")
    if source_attestation is not None:
        if source_mode == "EPHEMERAL":
            attestation_status = "EPHEMERAL_UNVERIFIABLE"
        elif source_mode == "PERSISTENT":
            if attestation_mode() != "PERSISTENT":
                attestation_status = "KEY_UNAVAILABLE"
            elif verify_manifest_attestation(data):
                attestation_ok = True
                attestation_status = "VERIFIED"
            else:
                attestation_ok = False
                attestation_status = "FAILED"
                issues.append("source attestation mismatch")
        else:
            attestation_ok = False
            attestation_status = "FAILED"
            issues.append("unsupported source attestation mode")
    return {
        "ok": linkage_ok and integrity_ok and authentication_ok is not False and attestation_ok is not False,
        "linkage_ok": linkage_ok,
        "integrity_ok": integrity_ok,
        "authentication_ok": authentication_ok,
        "authentication_status": authentication_status,
        "attestation_ok": attestation_ok,
        "attestation_status": attestation_status,
        "issues": issues,
    }


def write_sealed_manifest(manifest: VerificationManifest, destination: str | Path, audit_trace: dict[str, Any] | None = None) -> None:
    Path(destination).write_text(json.dumps(seal_manifest(manifest, audit_trace), sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_sealed_findings(findings: list[dict[str, Any]], metadata: dict[str, Any], destination: str | Path, audit_trace: dict[str, Any] | None = None) -> None:
    Path(destination).write_text(json.dumps(seal_findings(findings, metadata, audit_trace), sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read_and_verify(destination: str | Path) -> dict[str, Any]:
    return verify_sealed(load_json(destination, f"sealed manifest {destination}"))


FINDINGS_JSONL_SCHEMA_VERSION = "1.0"


def write_findings_jsonl(sealed: dict[str, Any], destination: str | Path) -> None:
    """Write one finding per line, self-describing and independent of context.

    Each line stamps its own schema version so a single extracted line (via
    grep, a diff of two runs, or a partial copy) stays interpretable without
    the surrounding sealed manifest. index/hash mirror the sealed chain entry
    so a line can be cross-referenced back to verification-manifest.sealed.json.
    """
    lines = []
    for entry in sealed.get("chain", []):
        record = {
            "findings_jsonl_schema_version": FINDINGS_JSONL_SCHEMA_VERSION,
            "index": entry["index"],
            "hash": entry["hash"],
            "finding": entry["finding"],
        }
        lines.append(json.dumps(record, sort_keys=True))
    Path(destination).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
