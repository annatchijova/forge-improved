"""Canonicalization and sealing of external multi-agent audit results."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from forge.canonical import canonical_json
from forge.agent_independence import load_and_validate
from forge.attestation import attest_manifest, attestation_mode, verify_manifest_attestation
from forge.disposition import AuditDisposition, unattested_external_disposition
from forge.io import load_json
from forge.sealing import verify_sealed, write_sealed_findings


def _digest(records: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json(records).encode("utf-8")).hexdigest()


def _external_findings(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"external findings artifact has no findings list: {path}")
    return findings


def operator_attest_external_findings(payload: dict[str, Any]) -> dict[str, Any]:
    """Explicitly attest an externally produced findings envelope as its operator.

    This is intentionally separate from finalization: the finalizer never
    auto-attests external content. Calling this function means the holder of
    FORGE_ATTESTATION_KEY reviewed and vouched for the supplied envelope.
    """
    if attestation_mode() != "PERSISTENT":
        raise ValueError("operator attestation requires FORGE_ATTESTATION_KEY")
    signed = dict(payload)
    signed["source_attestation_mode"] = "PERSISTENT"
    signed["source_attestation"] = attest_manifest(signed)
    return signed


def _external_analytic_provenance(payload: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    if payload.get("source_attestation") is None:
        return "UNATTESTED", ("codex_external analytical provenance is UNATTESTED",)
    if payload.get("source_attestation_mode") != "PERSISTENT":
        return "UNATTESTED", ("codex_external supplied no persistent operator attestation",)
    if attestation_mode() != "PERSISTENT":
        return "UNATTESTED", ("codex_external operator attestation cannot be verified because FORGE_ATTESTATION_KEY is unavailable",)
    if not verify_manifest_attestation(payload):
        return "UNATTESTED", ("codex_external operator attestation did not verify",)
    return "OPERATOR_ATTESTED", ()


def _native_findings(path: Path) -> list[dict[str, Any]]:
    data = load_json(path, f"native sealed findings {path}")
    chain = data.get("chain")
    if not isinstance(chain, list):
        raise ValueError(f"sealed artifact has no chain: {path}")
    return [entry["finding"] for entry in chain if isinstance(entry, dict) and isinstance(entry.get("finding"), dict)]


def build_canonical_findings(external: list[dict[str, Any]], native: list[dict[str, Any]], external_provenance: str = "UNATTESTED") -> list[dict[str, Any]]:
    """Keep source layers explicit while producing one deterministic finding set."""
    records: list[dict[str, Any]] = []
    for index, finding in enumerate(external):
        records.append({"record_id": f"codex_external:{finding.get('id', index + 1)}", "source_layer": "codex_external", "analytic_provenance": external_provenance, "finding": finding})
    for index, finding in enumerate(native):
        records.append({"record_id": f"forge_native:{index}", "source_layer": "forge_native", "analytic_provenance": "FORGE_NATIVE", "finding": finding})
    return records


def finalize_multi_agent_run(run_dir: str | Path, required_agents: list[str], external_findings_path: str | Path | None = None, native_sealed_path: str | Path | None = None, agent_results_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate independence, canonicalize both layers, and seal the result."""
    root = Path(run_dir)
    results_root = Path(agent_results_dir) if agent_results_dir is not None else root / "agent-results"
    validated = load_and_validate(results_root, required_agents)
    independence_path = root / "agent-independence.json"
    independence_path.write_text(json.dumps(validated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    external_path = Path(external_findings_path) if external_findings_path else root / "findings.json"
    native_path = Path(native_sealed_path) if native_sealed_path else root / "verification-manifest.sealed.json"
    native_sealed = load_json(native_path, f"native sealed findings {native_path}")
    native_verification = verify_sealed(native_sealed)
    if not native_verification["ok"]:
        raise ValueError(f"native sealed artifact is not verified: {native_verification['issues']}")
    external_payload = load_json(external_path, f"external findings {external_path}")
    external = _external_findings(external_payload, external_path)
    external_provenance, external_limitations = _external_analytic_provenance(external_payload)
    native = _native_findings(native_path)
    native_attestation = native_verification["attestation_status"]
    native_limitations: tuple[str, ...] = ()
    if native_attestation != "VERIFIED":
        native_limitations = (f"forge_native assembly attestation: {native_attestation}",)
    records = build_canonical_findings(external, native, external_provenance)
    finding_set_digest = _digest(records)
    disposition: AuditDisposition | None = None
    if external and external_provenance == "UNATTESTED":
        disposition = unattested_external_disposition(external_limitations)
    canonical = {
        "schema_version": "1.0",
        "finding_set_digest": finding_set_digest,
        "independence": validated,
        "source_layers": {"codex_external": len(external), "forge_native": len(native)},
        "analytic_provenance": {"codex_external": external_provenance, "forge_native": "FORGE_NATIVE"},
        "native_assembly_attestation": native_attestation,
        "limitations": list(external_limitations + native_limitations),
        "disposition": disposition.to_dict() if disposition else None,
        "records": records,
    }
    canonical_path = root / "canonical-findings.json"
    canonical_path.write_text(json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # The source findings file becomes the final, canonical set at closeout.
    # External hypotheses survive as an explicit source layer in `records`.
    (root / "findings.json").write_text(json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trace_path = root / "audit-trace.json"
    if trace_path.is_file():
        trace = load_json(trace_path, f"audit trace {trace_path}")
    else:
        trace = {"trace_version": "1.0", "run_id": "external-multi-agent", "started_at": int(time.time()), "events": []}
    events = trace.setdefault("events", [])
    sequence = max((int(event.get("sequence", -1)) for event in events if isinstance(event, dict)), default=-1) + 1
    timestamp = int(time.time())
    events.append({"kind": "external_agents_validated", "sequence": sequence, "timestamp": timestamp, "payload": {"agents": validated["agents"], "work_product_digests": validated["work_product_digests"]}})
    events.append({"kind": "canonical_finding_set_created", "sequence": sequence + 1, "timestamp": timestamp, "payload": {"finding_set_digest": finding_set_digest, "source_layers": canonical["source_layers"]}})
    trace_path.write_text(json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sealed_path = root / "verification-manifest.canonical.sealed.json"
    write_sealed_findings(records, {"schema_version": "1.0", "finding_set_digest": finding_set_digest, "root": str(root), "source_layers": canonical["source_layers"], "analytic_provenance": canonical["analytic_provenance"], "native_assembly_attestation": native_attestation, "disposition": canonical["disposition"]}, sealed_path, trace)
    canonical_verification = verify_sealed(load_json(sealed_path, f"canonical sealed findings {sealed_path}"))
    report_lines = [
        "# Forge canonical multi-agent audit",
        "",
        "## Status",
        "",
        "**ABSTAINED.** The canonical set preserves external Codex hypotheses and native Forge observations; no static candidate is promoted to confirmed without induction.",
        "",
        f"Finding-set digest: `{finding_set_digest}`",
        f"External Codex records: {len(external)}",
        f"Native Forge records: {len(native)}",
        f"Canonical assembly attestation: `{canonical_verification['attestation_status']}`.",
        f"External analytical provenance: `{external_provenance}`.",
        "",
        "## Findings by source layer",
        "",
    ]
    for layer in ("codex_external", "forge_native"):
        report_lines.extend([f"### {layer}", ""])
        for record in records:
            if record["source_layer"] != layer:
                continue
            finding = record["finding"]
            statement = finding.get("statement") or finding.get("description") or "No statement supplied"
            status = finding.get("epistemic_status") or finding.get("epistemic_level") or "UNDETERMINED"
            report_lines.append(f"- `{record['record_id']}` — **{status}** — {statement}")
        report_lines.append("")
    report_lines.extend([
        "## Integrity and independence",
        "",
        "- External agent independence: `INDEPENDENCE_VERIFIED`.",
        "- Canonical finding set: sealed in `verification-manifest.canonical.sealed.json`.",
        "- The canonical seal includes the updated external-agent audit trace.",
        "- Assembly attestation and analytical provenance are separate claims.",
        "- The seal proves artifact integrity, not finding correctness or an external layer's analytical provenance.",
    ])
    report_path = root / "report.md"
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    report_json = root / "report.json"
    status = disposition.status if disposition else "CANONICAL_FINDINGS_SEALED"
    report_json.write_text(json.dumps({"finding_set_digest": finding_set_digest, "source_layers": canonical["source_layers"], "analytic_provenance": canonical["analytic_provenance"], "disposition": canonical["disposition"], "records": records, "status": status}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"status": status, "finding_set_digest": finding_set_digest, "source_layers": canonical["source_layers"], "analytic_provenance": canonical["analytic_provenance"], "disposition": canonical["disposition"], "independence": str(independence_path), "canonical": str(canonical_path), "sealed": str(sealed_path), "trace": str(trace_path), "report": str(report_path), "report_json": str(report_json)}


__all__ = ("build_canonical_findings", "finalize_multi_agent_run", "operator_attest_external_findings")
