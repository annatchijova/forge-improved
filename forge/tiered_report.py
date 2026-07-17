"""Presentation-only tiers over an existing sealed FORGE artifact."""
from __future__ import annotations

import base64
from collections import Counter
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import shlex
from typing import Any

from forge.detector_scope import detector_scope_statement
from forge.io import load_json
from forge.findings_narrator import narrate_loaded_sealed_findings
from forge.sealing import verify_sealed

MODES = ("summary", "standard", "extended", "json")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _load(path: Path) -> dict[str, Any]:
    return load_json(path, f"report artifact {path}")


def findings_from_sealed(sealed: dict[str, Any]) -> list[dict[str, Any]]:
    """The sole finding source for every tier; never recomputed by rendering."""
    return [entry.get("finding", {}) for entry in sealed.get("chain", [])]


def canonical_findings_bytes(findings: list[dict[str, Any]]) -> bytes:
    return json.dumps(findings, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sidecar(sealed_path: Path, name: str) -> dict[str, Any] | None:
    candidate = sealed_path.parent / name
    try:
        return _load(candidate)
    except (OSError, json.JSONDecodeError):
        return None


def _per_module_coverage(sealed_path: Path) -> dict[str, Any] | None:
    triage = _sidecar(sealed_path, "triage-manifest.json")
    coverage = _sidecar(sealed_path, "coverage-report.json")
    if not triage and not coverage:
        return None
    modules = {item.get("path", "unknown"): {"triage": item.get("module_class", "unknown")} for item in (triage or {}).get("modules", [])}
    for reason, paths in (coverage or {}).get("skipped_reasons", {}).items():
        for path in paths:
            modules.setdefault(path, {})["coverage"] = reason
    return dict(sorted(modules.items()))


def _status_tone(status: Any) -> str:
    normalized = str(status or "UNSPECIFIED").upper()
    if normalized.startswith("ABSTAIN") or normalized.startswith("PARTIAL"):
        return "partial"
    if normalized in {"FAILED", "BLOCKED"}:
        return "fail"
    if normalized.startswith("COMPLETE") or normalized in {"PASSED", "VERIFIED"}:
        return "ok"
    return "neutral"


def _severity(finding: dict[str, Any]) -> str:
    value = str(finding.get("severity", "MEDIUM")).upper()
    return value if value in SEVERITY_ORDER else "INFO"


def _display_groups(findings: list[dict[str, Any]]) -> list[tuple[dict[str, Any], int, tuple[str, ...]]]:
    """Group one repeated cause while preserving every sealed source location."""
    grouped: dict[str, tuple[dict[str, Any], int, list[str]]] = {}
    for finding in findings:
        evidence = finding.get("evidence", [])
        primary = evidence[0] if evidence else {}
        key = json.dumps({"module_path": finding.get("module_path"), "description": finding.get("description"), "severity": _severity(finding), "category": finding.get("category"), "outcome": finding.get("outcome")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        representative, count, locations = grouped.get(key, (finding, 0, []))
        source = str(primary.get("source", finding.get("module_path", "unknown")))
        if source not in locations:
            locations.append(source)
        grouped[key] = (representative, count + 1, locations)
    return [(finding, count, tuple(locations)) for finding, count, locations in grouped.values()]


def _generated_at(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return "unknown"


def _overview_html(manifest: dict[str, Any], coverage: dict[str, Any] | None, findings: list[dict[str, Any]], display_groups: list[tuple[dict[str, Any], int, tuple[str, ...]]], verification_ok: bool) -> str:
    """Render structured audit facts before a reader enters detailed cards."""
    if not verification_ok:
        cards = [("Artifact state", "Verification failed"), ("Finding records", "Withheld"), ("Next action", "Inspect the raw artifact in a controlled workflow")]
    else:
        counts = Counter(_severity(finding) for finding in findings)
        highest = next((severity for severity in SEVERITY_ORDER if counts[severity]), "NONE")
        if coverage:
            eligible = coverage.get("eligible_source_files", coverage.get("files_discovered", 0))
            parsed = coverage.get("files_analyzed", 0)
            connected = coverage.get("connected_alive_modules", 0)
            scope = f"source {parsed}/{eligible} parsed · detector scope {connected}/{eligible} CONNECTED_ALIVE"
        else:
            scope = "Unavailable"
        cards = [("Repository", str(manifest.get("root", "unknown"))), ("Generated", _generated_at(manifest.get("generated_at_epoch"))), ("Sealed records", str(len(findings))), ("Distinct review items", str(len(display_groups))), ("Highest severity", highest), ("Scope", scope)]
    statuses = Counter(str(finding.get("epistemic_level", "UNSPECIFIED")) for finding in findings)
    legend = "".join(
        f"<span class='legend-item'><b>{html.escape(label)}</b> {count}</span>"
        for label, count in sorted(statuses.items())
    ) or "<span class='legend-item'>No lead statuses recorded</span>"
    return "<section id='overview' class='overview'><p class='section-kicker'>Review overview</p><h2>What this audit recorded</h2><p class='overview-note'><strong>Read this as an evidence queue, not a bug count.</strong> Lead status separates structural observations from hypotheses and protocol gaps; adjudication remains a human/agent review step.</p><div class='overview-grid'>" + "".join("<div class='overview-card'><span>" + html.escape(label) + "</span><strong>" + html.escape(value) + "</strong></div>" for label, value in cards) + f"</div><div class='status-legend' aria-label='Lead status breakdown'>{legend}</div></section>"


def _finding_html(finding: dict[str, Any], extended: bool, root: str, duplicate_count: int = 1, source_locations: tuple[str, ...] = ()) -> str:
    evidence = finding.get("evidence", [])
    primary = evidence[0] if evidence else {}
    severity = _severity(finding)
    source_location = str(primary.get("source", finding.get("module_path", "unknown")))
    reproduction = f"forge audit {shlex.quote(root)} --output forge-run"
    duplicate_note = f"<p class='duplicate-note'>Grouped {duplicate_count} related sealed records for review. The canonical artifact retains all {duplicate_count} records.</p>" if duplicate_count > 1 else ""
    additional_locations = "<p class='duplicate-note'>Also recorded at: " + ", ".join("<code>" + html.escape(location) + "</code>" for location in source_locations[1:]) + ".</p>" if len(source_locations) > 1 else ""
    body = [
        f"<div class='finding-heading'><h3>{html.escape(str(finding.get('module_path', 'unknown')))}</h3><span class='severity-badge severity-{severity.lower()}'>{severity}</span></div>",
        f"<p><strong>Lead status:</strong> {html.escape(str(finding.get('epistemic_level', 'UNSPECIFIED')))} · Agent: {html.escape(str(finding.get('agent', 'bug_investigator')))} · Category: {html.escape(str(finding.get('category', '')))} · Outcome: {html.escape(str(finding.get('outcome', 'OBSERVED')))}</p>",
        f"<p>{html.escape(str(finding.get('description', '')))}</p>", duplicate_note, additional_locations,
        f"<pre>{html.escape(source_location)}: {html.escape(str(primary.get('detail', '')))}</pre>",
        "<details class='reproduction'><summary>Review actions</summary><p>Source location: <code>" + html.escape(source_location) + "</code></p><p>Reproduce this audit:</p><pre>" + html.escape(reproduction) + "</pre></details>",
    ]
    if extended:
        body.append(f"<details open><summary>Reasoning chain</summary><pre>{html.escape(str(finding.get('reasoning', '')))}</pre><pre>{html.escape(json.dumps(evidence, indent=2, sort_keys=True))}</pre></details>")
    return "<article class='finding severity-card-" + severity.lower() + "'>" + "".join(body) + "</article>"


def render_tiered_report(sealed_path: str | Path, mode: str, destination: str | Path | None = None) -> Path:
    if mode not in MODES:
        raise ValueError(f"unsupported report mode: {mode}")
    source = Path(sealed_path)
    destination = Path(destination) if destination else source.with_name(f"{source.stem}.{mode}" + (".json" if mode == "json" else ".html"))
    if mode == "json":
        destination.write_bytes(source.read_bytes())
        return destination

    sealed = _load(source)
    findings = findings_from_sealed(sealed)
    verification = verify_sealed(sealed)
    narration = narrate_loaded_sealed_findings(sealed, source)
    display_findings = findings if verification["ok"] else []
    display_groups = _display_groups(display_findings)
    manifest = sealed.get("manifest", {})
    payload = base64.b64encode(canonical_findings_bytes(display_findings)).decode("ascii")
    if verification.get("ok"):
        seal_text = "Authenticated chain verified" if verification.get("authentication_status") == "VERIFIED" else "Chain verified (not externally authenticated)"
    else:
        seal_text = "FAILED: " + "; ".join(verification.get("issues", []))
    metrics = _sidecar(source, "metrics.json") or {}
    disposition_status = metrics.get("audit_disposition", {}).get("status") or ("VERIFIED" if verification.get("ok") else "FAILED")
    disposition_reason = str(metrics.get("audit_disposition", {}).get("reason", ""))
    coverage = _sidecar(source, "coverage-report.json")
    eligible_source = coverage.get("eligible_source_files", coverage.get("files_discovered", 0)) if coverage else 0
    source_scope = (
        f"Source coverage: {coverage.get('files_analyzed', 0)}/{eligible_source} eligible files parsed; "
        f"detector scope: {coverage.get('connected_alive_modules', 0)}/{eligible_source} CONNECTED_ALIVE modules; "
        f"{coverage.get('detector_scope_excluded_modules', 0)} modules outside detector scope; "
        f"discovery accounting: {coverage.get('files_discovered', 0)} discovered. File and module counts are different measures."
        if coverage else "Source coverage: unavailable"
    )
    status_tone = _status_tone(disposition_status)
    root = str(manifest.get("root", "."))
    attestation_text = "Assembly attestation: " + str(verification.get("attestation_status", "NOT_PRESENT"))
    external_provenance = manifest.get("analytic_provenance", {}).get("codex_external")
    provenance_text = "External analytical provenance: " + str(external_provenance) if external_provenance else ""
    findings_html = "".join(_finding_html(finding, mode == "extended", root, count, locations) for finding, count, locations in display_groups) or "<p>No surviving findings in this artifact.</p>" if verification["ok"] else "<p>Finding records are withheld because this artifact failed verification. Inspect the raw artifact only in a controlled forensic workflow.</p>"

    navigation = ["overview", "seal", "detector-scope", "findings", "narrated-summary", "limitations"]
    if mode in {"standard", "extended"}:
        navigation += ["discarded", "coverage"]
    if mode == "extended":
        navigation += ["contracts", "trace"]
    nav_html = "<nav aria-label='Report sections'>" + "".join("<a href='#" + section + "'>" + html.escape(section.replace("-", " ").title()) + "</a>" for section in navigation) + "</nav>"

    sections = [
        _overview_html(manifest, coverage, display_findings, display_groups, verification["ok"]),
        "<section id='seal'><h2>Seal status</h2><p class='status-" + status_tone + "'>" + html.escape(str(disposition_status)) + " · " + html.escape(seal_text) + "<br>" + html.escape(attestation_text) + ("<br>" + html.escape(provenance_text) if provenance_text else "") + "<br>" + html.escape(disposition_reason) + "<br>" + html.escape(source_scope) + "</p></section>",
        "<section id='detector-scope'><h2>Detector scope</h2><p>" + html.escape(detector_scope_statement()) + "</p><p>A clean disposition means no surviving finding within both the declared source scope and detector scope. It is not a repository-wide correctness or safety certification.</p></section>",
        "<section id='findings'><h2>Findings</h2>" + findings_html + "</section>",
        "<section id='narrated-summary' class='narrated-summary'><p class='prose-label'>💬 Narrated summary (not verified)</p><h2>Reader-oriented summary</h2><p>" + html.escape(narration.narrative) + "</p><p>This deterministic prose is derived after verification from the sealed finding set only. It is not evidence, is not sealed, and cannot change a finding, severity, disposition, or audit decision.</p>" + ("<ul>" + "".join("<li>" + html.escape(issue) + "</li>" for issue in narration.verification_issues) + "</ul>" if narration.verification_issues else "") + "</section>",
        "<section id='limitations'><h2>Limitations</h2><ul>" + "".join(f"<li>{html.escape(str(item))}</li>" for item in sealed.get("limitations", [])) + "</ul></section>",
    ]
    if mode in {"standard", "extended"}:
        discarded = manifest.get("discarded", [])
        coverage = _per_module_coverage(source)
        sections += ["<section id='discarded'><h2>Discarded hypotheses</h2><pre>" + html.escape(json.dumps(discarded, indent=2, sort_keys=True)) + "</pre></section>", "<section id='coverage'><h2>Per-module coverage</h2><pre>" + (html.escape(json.dumps(coverage, indent=2, sort_keys=True)) if coverage else "Triage/coverage sidecars unavailable") + "</pre></section>"]
    if mode == "extended":
        skills = _sidecar(source, "skills-runtime.json")
        sections += ["<section id='contracts'><h2>Contract evaluations and governance applicability</h2><pre>" + (html.escape(json.dumps(skills, indent=2, sort_keys=True)) if skills else "Skill runtime sidecar unavailable") + "</pre></section>", "<section id='trace'><h2>Metrics and audit trace</h2><p>Complete telemetry is available in <a href='metrics.json'>metrics.json</a>; this HTML tier does not duplicate the sealed chain.</p><pre>" + html.escape(json.dumps({"manifest": {"forge_version": manifest.get("forge_version"), "schema_version": manifest.get("schema_version")}, "audit_trace": sealed.get("audit_trace", "Audit trace unavailable")}, indent=2, sort_keys=True)) + "</pre></section>"]

    style = """
<style>
:root{--bg:#E3B8B8;--bg-elevated:#FFFFFF;--bg-sunken:#E8E9E3;--ink:#1C2222;--ink-muted:#5B6460;--rule:#D5D6CE;--accent:#2B5D63;--ok:#3C7A52;--fail:#A8501C;--critical:#812F3A;--high:#B04A2C;--medium:#9A6B18;--low:#2B5D63;--info:#5B6460;--serif:Georgia,"Times New Roman",serif;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--sans);-webkit-font-smoothing:antialiased}.wrap{max-width:1180px;margin:0 auto;padding:0 24px 56px}header{border-bottom:2px solid var(--ink);padding:40px 0 16px;margin-bottom:20px}h1{font:600 clamp(28px,4vw,40px) var(--serif);margin:0 0 18px}h2{font:600 21px var(--serif);color:var(--accent);border-bottom:1px solid var(--rule);padding-bottom:10px}h3{font:600 17px var(--serif);margin:0}section{background:var(--bg-elevated);border:1px solid var(--rule);border-radius:3px;margin:24px 0;padding:22px 24px;box-shadow:0 4px 14px rgba(28,34,34,.06)}nav{display:flex;flex-wrap:wrap;gap:8px}nav a{border:1px solid var(--rule);border-radius:14px;padding:4px 9px;background:var(--bg-elevated);color:var(--accent);font:11px var(--mono);text-decoration:none;text-transform:uppercase;letter-spacing:.04em}nav a:hover{background:var(--bg-sunken)}.section-kicker{margin:0 0 3px;color:var(--ink-muted);font:11px var(--mono);text-transform:uppercase;letter-spacing:.11em}.overview-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.overview-card{border:1px solid var(--rule);background:var(--bg-sunken);padding:11px 12px;border-radius:3px}.overview-card span{display:block;color:var(--ink-muted);font:11px var(--mono);text-transform:uppercase;letter-spacing:.04em}.overview-card strong{display:block;margin-top:3px;overflow-wrap:anywhere;font-size:15px}#seal p{display:inline-block;background:var(--bg-sunken);color:var(--ink-muted);border:1px solid var(--rule);border-radius:14px;padding:6px 12px;font:12px var(--mono);letter-spacing:.04em}#seal p.status-ok{background:#DFEDE2;color:#2A5A3C;border-color:#A9C9B0}#seal p.status-partial{background:#FFF4E9;color:#7A3A14;border-color:#D89A70}#seal p.status-fail{background:#F8E5E5;color:#8B2F2F;border-color:#D39A9A}.finding{background:var(--bg);border:1px solid var(--rule);border-left:5px solid var(--accent);border-radius:3px;padding:14px 18px;margin:14px 0}.finding.severity-card-critical{border-left-color:var(--critical)}.finding.severity-card-high{border-left-color:var(--high)}.finding.severity-card-medium{border-left-color:var(--medium)}.finding.severity-card-low{border-left-color:var(--low)}.finding.severity-card-info{border-left-color:var(--info)}.finding-heading{display:flex;justify-content:space-between;gap:12px;align-items:center}.finding p:first-of-type{color:var(--ink-muted);font:12px var(--mono)}.severity-badge{border-radius:12px;padding:3px 8px;color:#fff;font:11px var(--mono);letter-spacing:.04em}.severity-critical{background:var(--critical)}.severity-high{background:var(--high)}.severity-medium{background:var(--medium)}.severity-low{background:var(--low)}.severity-info{background:var(--info)}.duplicate-note{margin:8px 0;color:var(--ink-muted);font-size:13px}.reproduction{margin-top:10px}.reproduction summary{cursor:pointer;color:var(--accent);font:12px var(--mono)}.reproduction p{margin:8px 0}.reproduction code{overflow-wrap:anywhere}.finding details pre{margin-bottom:0}pre{background:var(--bg-sunken);border-radius:3px;padding:12px 14px;overflow:auto;white-space:pre-wrap;font:13px/1.5 var(--mono)}.narrated-summary{background:#FFF7EC;border-left:5px solid #B87A23}.prose-label{margin:0 0 5px;color:#805113;font:11px var(--mono);letter-spacing:.11em;text-transform:uppercase;font-weight:700}#limitations h2,#discarded h2{color:var(--fail)}@media (max-width:700px){.wrap{padding:0 14px 36px}.overview-grid{grid-template-columns:repeat(2,minmax(0,1fr))}section{padding:18px}.finding-heading{align-items:flex-start;flex-direction:column}.severity-badge{align-self:flex-start}}
 .skip-link{position:absolute;left:-9999px;top:8px;background:var(--ink);color:#fff;padding:8px 12px;z-index:10}.skip-link:focus{left:8px}.overview-note{background:#DCE7E6;border-left:4px solid var(--accent);padding:10px 13px;font-size:14px}.status-legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.legend-item{background:var(--bg-sunken);border:1px solid var(--rule);border-radius:999px;padding:5px 9px;color:var(--ink-muted);font:11px var(--mono)}.legend-item b{color:var(--ink)}section{scroll-margin-top:18px}@media print{body{background:#fff;color:#000}.wrap{max-width:none;padding:0}section{box-shadow:none;break-inside:avoid}nav,.finding-toolbar,.skip-link{display:none!important}.finding{break-inside:avoid}a{color:#000;text-decoration:none}}
</style>
"""
    document = "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>FORGE " + mode + " report</title>" + style + "</head><body><a class='skip-link' href='#overview'>Skip to report overview</a><div class='wrap'><header><h1>FORGE " + mode + " report</h1>" + nav_html + "</header>" + "".join(sections) + f"<meta id='forge-findings' data-canonical-base64='{payload}'></div></body></html>"
    destination.write_text(document, encoding="utf-8")
    return destination


def rendered_finding_bytes(path: str | Path, mode: str) -> bytes:
    """Test/consumer helper proving the renderer preserved the sealed finding set."""
    raw = Path(path).read_bytes()
    if mode == "json":
        return canonical_findings_bytes(findings_from_sealed(load_json(path, f"report artifact {path}")))
    marker = b"data-canonical-base64='"
    encoded = raw.split(marker, 1)[1].split(b"'", 1)[0]
    return base64.b64decode(encoded)
