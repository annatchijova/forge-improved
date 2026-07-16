"""Canonicalization and sealing of external multi-agent audit results."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from forge.canonical import canonical_json
from forge.agent_independence import load_and_validate
from forge.io import load_json
from forge.sealing import verify_sealed, write_sealed_findings


def _digest(records: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json(records).encode("utf-8")).hexdigest()


def _external_findings(path: Path) -> list[dict[str, Any]]:
    data = load_json(path, f"external findings {path}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"external findings artifact has no findings list: {path}")
    return findings


def _native_findings(path: Path) -> list[dict[str, Any]]:
    data = load_json(path, f"native sealed findings {path}")
    chain = data.get("chain")
    if not isinstance(chain, list):
        raise ValueError(f"sealed artifact has no chain: {path}")
    return [entry["finding"] for entry in chain if isinstance(entry, dict) and isinstance(entry.get("finding"), dict)]


def build_canonical_findings(external: list[dict[str, Any]], native: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep source layers explicit while producing one deterministic finding set."""
    records: list[dict[str, Any]] = []
    for index, finding in enumerate(external):
        records.append({"record_id": f"codex_external:{finding.get('id', index + 1)}", "source_layer": "codex_external", "finding": finding})
    for index, finding in enumerate(native):
        records.append({"record_id": f"forge_native:{index}", "source_layer": "forge_native", "finding": finding})
    return records


def finalize_multi_agent_run(run_dir: str | Path, required_agents: list[str], external_findings_path: str | Path | None = None, native_sealed_path: str | Path | None = None) -> dict[str, Any]:
    """Validate independence, canonicalize both layers, and seal the result."""
    root = Path(run_dir)
    validated = load_and_validate(root / "agent-results", required_agents)
    independence_path = root / "agent-independence.json"
    independence_path.write_text(json.dumps(validated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    external_path = Path(external_findings_path) if external_findings_path else root / "findings.json"
    native_path = Path(native_sealed_path) if native_sealed_path else root / "verification-manifest.sealed.json"
    native_sealed = load_json(native_path, f"native sealed findings {native_path}")
    native_verification = verify_sealed(native_sealed)
    if not native_verification["ok"]:
        raise ValueError(f"native sealed artifact is not verified: {native_verification['issues']}")
    external = _external_findings(external_path)
    native = _native_findings(native_path)
    records = build_canonical_findings(external, native)
    finding_set_digest = _digest(records)
    canonical = {
        "schema_version": "1.0",
        "finding_set_digest": finding_set_digest,
        "independence": validated,
        "source_layers": {"codex_external": len(external), "forge_native": len(native)},
        "records": records,
    }
    canonical_path = root / "canonical-findings.json"
    canonical_path.write_text(json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    write_sealed_findings(records, {"schema_version": "1.0", "finding_set_digest": finding_set_digest, "root": str(root), "source_layers": canonical["source_layers"]}, sealed_path, trace)
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
        "- The seal proves artifact integrity, not finding correctness.",
    ])
    report_path = root / "report.md"
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    report_json = root / "report.json"
    report_json.write_text(json.dumps({"finding_set_digest": finding_set_digest, "source_layers": canonical["source_layers"], "records": records, "status": "ABSTAINED"}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"status": "CANONICAL_FINDINGS_SEALED", "finding_set_digest": finding_set_digest, "source_layers": canonical["source_layers"], "independence": str(independence_path), "canonical": str(canonical_path), "sealed": str(sealed_path), "trace": str(trace_path), "report": str(report_path), "report_json": str(report_json)}


__all__ = ("build_canonical_findings", "finalize_multi_agent_run")
