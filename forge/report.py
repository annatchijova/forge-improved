"""Self-contained, evidence-first HTML report renderer for module 5."""
from __future__ import annotations

import html
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_EXAMINATIONS_DETAIL_THRESHOLD = 15
_EXAMINATIONS_STATUS_ORDER = (
    "examined_with_findings", "hypothesis_discarded_benign", "no_hypothesis_generated",
    "examined_clean", "excluded_by_policy", "excluded_by_scope",
)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

from forge.sealing import verify_sealed
from forge.io import load_json


def _e(value: Any) -> str:
    return html.escape(str(value))


def _option_tags(values: list[str]) -> str:
    return "".join(f'<option value="{_e(value)}">{_e(value)}</option>' for value in values)


def _load(path: str | Path) -> dict[str, Any]:
    return load_json(path, f"report artifact {path}")


def _iso(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return "unknown"


def _blame(root: str, module_path: str, line: int) -> str | None:
    try:
        raw = subprocess.check_output(
            ["git", "-C", root, "blame", "--line-porcelain", "-L", f"{line},{line}", "--", module_path],
            stderr=subprocess.DEVNULL, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "Git blame timed out after 30 seconds; report continues with source evidence only."
    except (OSError, subprocess.SubprocessError):
        return None
    fields = {}
    for row in raw.splitlines():
        key, _, value = row.partition(" ")
        if key in {"author", "author-time", "summary"}:
            fields[key] = value
        elif not fields.get("commit") and len(row.split()) >= 3 and not row.startswith(("author ", "author-time ")):
            fields["commit"] = row.split()[0]
    if not fields:
        return None
    return f"author={fields.get('author', 'unknown')}; date={fields.get('author-time', 'unknown')}; commit={fields.get('commit', 'unknown')}"


def _hypothesis_for(hypotheses: list[dict[str, Any]], module: str, line: int) -> dict[str, Any] | None:
    return next((h for h in hypotheses if h.get("module_path") == module and line in h.get("file_lines", [])), None)


def _examinations_html(examinations: dict[str, str]) -> str:
    if not examinations:
        return ""
    counts = Counter(examinations.values())
    ordered_statuses = [s for s in _EXAMINATIONS_STATUS_ORDER if s in counts]
    ordered_statuses += sorted(s for s in counts if s not in _EXAMINATIONS_STATUS_ORDER)
    summary = ", ".join(f"{_e(status)}: {_e(counts[status])}" for status in ordered_statuses)
    out = f"<div class=\"examinations-summary\">{_e(len(examinations))} module(s) examined — {summary}</div>"
    if len(examinations) <= _EXAMINATIONS_DETAIL_THRESHOLD:
        rows = "".join(f"<li><code>{_e(path)}</code>: {_e(status)}</li>" for path, status in sorted(examinations.items()))
        out += f"<details><summary>Per-module detail</summary><ul>{rows}</ul></details>"
    else:
        out += (
            f"<p><small>Per-module detail omitted above the {_EXAMINATIONS_DETAIL_THRESHOLD}-module inline "
            "threshold; the full per-module breakdown is in the coverage/verification JSON artifacts on disk.</small></p>"
        )
    return out


def _metric_block(agent: str, values: Any) -> str:
    if not isinstance(values, dict):
        return f"<li><strong>{_e(agent)}</strong>: {_e(values)}</li>"
    examinations = values.get("examinations")
    other = {k: v for k, v in values.items() if k != "examinations"}
    other_text = f": {_e(other)}" if other else ""
    return f"<li><strong>{_e(agent)}</strong>{other_text}{_examinations_html(examinations)}</li>"


def _bar_rows(values: Any) -> str:
    if not isinstance(values, dict) or not values:
        return '<p class="empty-state">No data recorded.</p>'
    numeric = [(str(key), value) for key, value in values.items() if isinstance(value, (int, float))]
    if not numeric:
        return '<p class="empty-state">No numeric data recorded.</p>'
    maximum = max(value for _, value in numeric) or 1
    rows = []
    for label, value in sorted(numeric, key=lambda item: (-item[1], item[0])):
        width = max(4, min(100, (value / maximum) * 100))
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{_e(label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{width:.2f}%"></span></span>'
            f'<strong class="bar-value">{_e(value)}</strong></div>'
        )
    return "".join(rows)


def _status_tone(status: Any) -> str:
    """Return a presentation tone without conflating seal integrity and outcome."""
    normalized = str(status or "UNSPECIFIED").upper()
    if normalized.startswith("ABSTAIN") or normalized.startswith("PARTIAL"):
        return "partial"
    if normalized in {"FAILED", "BLOCKED"}:
        return "fail"
    if normalized.startswith("COMPLETE") or normalized in {"PASSED", "VERIFIED"}:
        return "ok"
    return "neutral"


def _finding_card(finding: dict[str, Any], hypotheses: list[dict[str, Any]], root: str) -> str:
    evidence = finding.get("evidence", [])
    source = next((item for item in evidence if item.get("kind") == "source"), evidence[0] if evidence else {})
    source_ref = source.get("source", "unknown")
    module, _, line_text = source_ref.rpartition(":")
    try:
        line = int(line_text)
    except ValueError:
        line = 0
    hypothesis = _hypothesis_for(hypotheses, finding.get("module_path", module), line)
    blame = _blame(root, module or finding.get("module_path", ""), line) if line else None
    blame_html = _e(blame) if blame else "Git blame unavailable for this line; report continues with source evidence only."
    falsifier = hypothesis.get("falsification_test", "No originating hypothesis test was found in the supplied manifest.") if hypothesis else "No originating hypothesis test was found in the supplied manifest."
    severity = str(finding.get("severity", "MEDIUM")).upper()
    agent = str(finding.get("agent", "bug_investigator"))
    epistemic = str(finding.get("epistemic_level", ""))
    provenance = ", ".join(str(item) for item in finding.get("provenance", ())) or "not recorded"
    evidence_roles = ", ".join(f"{item.get('role', 'primary')}: {item.get('source', 'unknown')}" for item in evidence) or "none"
    searchable = " ".join(str(finding.get(key, "")) for key in ("module_path", "description", "reasoning", "agent", "epistemic_level", "severity"))
    return f"""<article class=\"finding severity-card-{_e(severity.lower())}\" data-agent=\"{_e(agent)}\" data-severity=\"{_e(severity)}\" data-epistemic=\"{_e(epistemic)}\" data-search=\"{_e(searchable.lower())}\">
      <p><strong>Agent:</strong> {_e(finding.get('agent', 'bug_investigator'))}</p>
      <div><span class=\"badge severity-{_e(str(finding.get('severity', 'MEDIUM')).lower())}\">Severity: {_e(finding.get('severity', 'MEDIUM'))}</span> <span class=\"badge\"><strong>Lead status:</strong> {_e(finding.get('epistemic_level', 'UNSPECIFIED'))}</span> <span class=\"ref\">{_e(source_ref)}</span></div>
      <p><strong>Description (inference):</strong> {_e(finding.get('description', ''))}</p>
      <p><strong>Source observation:</strong> <code>{_e(source.get('detail', ''))}</code></p>
      <p><strong>Reasoning:</strong> {_e(finding.get('reasoning', ''))}</p>
      <p><strong>Evidence provenance:</strong> {_e(provenance)}<br/><strong>Evidence ledger:</strong> {_e(evidence_roles)}</p>
      <p><strong>Falsification test:</strong> {_e(falsifier)}</p>
      <p><strong>Additional evidence — git blame:</strong> {_e(blame_html)}</p>
    </article>"""


def render_report(triage_path: str | Path, hypotheses_path: str | Path, sealed_path: str | Path, destination: str | Path, coverage_path: str | Path | None = None, metrics: dict[str, Any] | None = None) -> None:
    triage = _load(triage_path)
    hypotheses_doc = _load(hypotheses_path)
    sealed = _load(sealed_path)
    coverage = _load(coverage_path) if coverage_path else None
    cost = None
    cost_path = Path(sealed_path).parent / "run-cost.json"
    if cost_path.exists():
        try:
            cost = _load(cost_path)
        except (OSError, ValueError, json.JSONDecodeError):
            cost = None
    metrics = metrics or {}
    seal = verify_sealed(sealed)
    manifest = sealed.get("manifest", {})
    findings = [entry.get("finding", {}) for entry in sealed.get("chain", [])]
    findings = sorted(findings, key=lambda item: (_SEVERITY_ORDER.get(str(item.get("severity", "MEDIUM")).upper(), 99), str(item.get("module_path", ""))))
    hypotheses = hypotheses_doc.get("hypotheses", [])
    root = triage.get("root", manifest.get("root", "."))
    finding_modules = {f.get("module_path") for f in findings}
    discarded = manifest.get("discarded", [])
    audited = hypotheses_doc.get("audited_modules", [])
    clean = [module for module in audited if module not in finding_modules]
    out_of_scope = [m for m in triage.get("modules", []) if m.get("module_class") != "CONNECTED_ALIVE"]
    families = ", ".join(manifest.get("ast_verified_families", [])) or "the implemented structural checks"
    seal_text = f"Chain integrity: VERIFIED ({len(sealed.get('chain', []))} entries, 0 issues)" if seal["ok"] else f"Chain integrity: FAILED ({len(sealed.get('chain', []))} entries, {len(seal['issues'])} issues): {'; '.join(seal['issues'])}"
    git_note = "Git blame is attempted per finding and is shown when available; unavailable blame is labeled rather than inferred."
    findings_html = "".join(_finding_card(f, hypotheses, root) for f in findings) or "<p>No surviving findings in the supplied sealed manifest.</p>"
    agents = sorted({str(f.get("agent", "bug_investigator")) for f in findings})
    severities = [name for name in _SEVERITY_ORDER if any(str(f.get("severity", "MEDIUM")).upper() == name for f in findings)]
    epistemic_levels = sorted({str(f.get("epistemic_level", "")) for f in findings if f.get("epistemic_level")})
    agent_options = _option_tags(agents)
    severity_options = _option_tags(severities)
    epistemic_options = _option_tags(epistemic_levels)
    filter_html = f"""<div class=\"finding-toolbar\" role=\"search\" aria-label=\"Finding filters\">
  <label>Search <input id=\"finding-search\" type=\"search\" placeholder=\"module, description, reasoning…\"></label>
  <label>Agent <select id=\"finding-agent\"><option value=\"\">All agents</option>{agent_options}</select></label>
  <label>Severity <select id=\"finding-severity\"><option value=\"\">All severities</option>{severity_options}</select></label>
  <label>Status <select id=\"finding-epistemic\"><option value=\"\">All statuses</option>{epistemic_options}</select></label>
  <span id=\"finding-count\" class=\"filter-count\">Showing {len(findings)} of {len(findings)}</span>
</div>"""
    discarded_html = "".join(f"<article class=\"discarded\"><strong>{_e(item.get('module_path'))}</strong><p>{_e(item.get('reason'))}</p></article>" for item in discarded) or "<p>No discarded hypotheses recorded.</p>"
    clean_html = "".join(f"<li>{_e(module)} — checked against: {_e(families)}</li>" for module in clean) or "<li>No audited module met the clean-module condition.</li>"
    scope_html = "".join(f"<article class=\"scope\"><strong>{_e(item.get('path'))}</strong> — {_e(item.get('module_class'))}. This module was outside CONNECTED_ALIVE scope for this run.</article>" for item in out_of_scope) or "<p>All triaged modules were in CONNECTED_ALIVE scope.</p>"
    limitations = "The seal shows that sealed findings were not altered after sealing; it does not show that findings are correct. It does not protect against a full cascade forgery or truncation with an edited reported_chain_length. <a href=\"DECISIONS.md\">DECISIONS.md</a> records the bounds."
    seal_class = "ok" if seal["ok"] else "fail"
    chain = sealed.get("chain", [])
    last_hash = chain[-1]["hash"] if chain else "GENESIS (empty chain)"
    integrity_text = "OK" if seal["ok"] else f"BROKEN — {'; '.join(seal['issues'])}"
    generated_at = _iso(manifest.get("generated_at_epoch"))
    ast_unverified = ", ".join(manifest.get("ast_unverified_families", [])) or "none recorded"

    info_rows = [
        ("Root", _e(root)),
        ("Forge version", _e(manifest.get("forge_version", "unknown"))),
        ("Schema version", f"{_e(manifest.get('schema_version', 'unknown'))} (hypotheses {_e(manifest.get('hypotheses_schema_version', 'unknown'))})"),
        ("Generated", _e(generated_at)),
        ("Chain entries", _e(sealed.get("reported_chain_length", len(chain)))),
        ("Chain integrity", integrity_text),
        ("Seal version", _e(sealed.get("seal_version", "unknown"))),
        ("Canonicalize version", _e(sealed.get("canonicalize_version", "unknown"))),
    ]
    coverage_summary = None
    if coverage:
        ratio = coverage.get("coverage_ratio", {})
        numerator, denominator = ratio.get('numerator', 0), ratio.get('denominator', 1)
        percent = (100 * numerator / denominator) if denominator else 0
        ratio_text = f"{numerator}/{denominator} ({percent:.1f}%)"
        coverage_summary = (coverage, ratio_text)
    # The detailed layered metrics are persisted as metrics.json. Keep the
    # HTML agent panel compact and route only the legacy per-agent accounting
    # through the examination-aware renderer; otherwise nested dictionaries
    # would reintroduce the large raw examination dump this panel avoids.
    display_metrics = metrics.get("agent_metrics", metrics)
    metrics_html = "".join(_metric_block(agent, values) for agent, values in display_metrics.items())
    info_table_html = "".join(f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in info_rows)
    summary_tiles_html = "".join(
        f'<div class="stat-tile {tone}"><div class="stat-number">{value}</div><div class="stat-label">{label}</div></div>'
        for value, label, tone in (
            (len(findings), "Surviving findings", "risk" if findings else "safe"),
            (len(discarded), "Discarded hypotheses", "caution" if discarded else "safe"),
            (len(audited), "Audited modules", "neutral"),
            (len(out_of_scope), "Out of scope", "muted"),
        )
    )
    coverage_section_html = ""
    if coverage_summary:
        coverage_data, ratio_text = coverage_summary
        detector_scope = int(coverage_data.get("connected_alive_modules", 0) or 0)
        scope_denominator = int(coverage_data.get("eligible_source_files", 0) or coverage_data.get("files_analyzed", 0) or 0)
        scope_percent = (100 * detector_scope / scope_denominator) if scope_denominator else 0
        coverage_section_html = (
            f'<section id="coverage"><h2>Coverage</h2>'
            f'<p class="section-lede">Semantic coverage means modules that received detector attention, not only files that parsed.</p>'
            f'<div class="coverage-hero"><div><strong>Source coverage</strong><b>{_e(ratio_text)}</b><span>eligible source files parsed</span></div><div><strong>Detector scope</strong><b>{_e(f"{detector_scope}/{scope_denominator} ({scope_percent:.1f}%)")}</b><span>CONNECTED_ALIVE modules receiving detector attention</span></div><small>{_e(coverage_data.get("detector_scope_excluded_modules", 0))} modules outside detector scope · {_e(coverage_data.get("files_skipped", 0))} files skipped · {_e(coverage_data.get("files_discovered", 0))} discovered. File and module counts are different measures.</small></div>'
            f'<p>Language coverage: {_e(coverage_data.get("language_coverage", {}))}</p>'
            f'<p>Skipped reasons: {_e(coverage_data.get("skipped_reasons", {}))}</p></section>'
        )

    objective_html = (
        f"<p>Verify the hypotheses generated for <code>{_e(root)}</code> against the implemented structural AST "
        f"checks (<code>{_e(families)}</code>), and seal the surviving findings into a tamper-evident chain. "
        f"{_e(len(audited))} module(s) audited; {_e(len(findings))} finding(s) survived; {_e(len(discarded))} "
        f"hypothesis/es discarded; {_e(len(out_of_scope))} module(s) out of scope.</p>"
    )

    summary_rows = "".join(
        f"<tr><td><code>{_e(f.get('module_path', 'unknown'))}</code></td><td>Finding — {_e(f.get('epistemic_level', ''))}</td><td>{_e(f.get('description', ''))}</td></tr>"
        for f in findings
    ) + "".join(
        f"<tr><td><code>{_e(item.get('module_path', 'unknown'))}</code></td><td>Discarded</td><td>{_e(item.get('reason', ''))}</td></tr>"
        for item in discarded
    )
    hypotheses_summary_html = (
        f"<table class=\"data-table\"><thead><tr><th>Label</th><th>Status</th><th>Outcome</th></tr></thead><tbody>{summary_rows}</tbody></table>"
        if summary_rows else "<p>No hypotheses were registered for this run.</p>"
    )

    quality_rows = [
        ("Audited modules", _e(len(audited))),
        ("Findings (surviving)", _e(len(findings))),
        ("Discarded hypotheses", _e(len(discarded))),
        ("Clean modules", _e(len(clean))),
        ("Out of scope", _e(len(out_of_scope))),
        ("AST-verified families", _e(families)),
        ("AST-unverified families", _e(ast_unverified)),
    ]
    induction_records = manifest.get("induction", [])
    if induction_records:
        quality_rows.append(("Induction", _e(Counter(item.get("status", "UNDETERMINED") for item in induction_records))))
    quality_metrics = metrics.get("quality", {})
    contract_ratio = quality_metrics.get("contract_coverage", {})
    if contract_ratio:
        quality_rows.append(("Contract coverage", f"{_e(contract_ratio.get('covered', 0))}/{_e(contract_ratio.get('total', 0))} — {_e(quality_metrics.get('contract_coverage_note', 'context unavailable'))}"))
    finding_counts = metrics.get("findings", {}).get("by_agent", {})
    if finding_counts:
        quality_rows.append(("Findings by agent", _e(finding_counts)))
    severity_counts = metrics.get("findings", {}).get("by_severity", {})
    if severity_counts:
        quality_rows.append(("Findings by severity", _e(severity_counts)))
    epistemic_counts = metrics.get("findings", {}).get("by_epistemic_level", {})
    if epistemic_counts:
        quality_rows.append(("Lead status breakdown", _e(epistemic_counts)))
    verification_metrics = metrics.get("agents", {}).get("verification", {})
    if verification_metrics:
        quality_rows.append(("Structural verification", _e({key: verification_metrics.get(key) for key in ("checks_passed", "checks_failed", "checks_unresolved") if key in verification_metrics})))
    quality_table_html = "".join(f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in quality_rows)
    degradation = metrics.get("honest_degradation", {})
    degradation_items = degradation.get("limitations", [])
    degradation_html = "".join(f"<li>{_e(item)}</li>" for item in degradation_items) or "<li>No additional degradation was recorded.</li>"
    repository_metrics = metrics.get("repository", {})
    skill_runtime = metrics.get("skill_runtime", {})
    findings_metrics = metrics.get("findings", {})
    disposition = metrics.get("audit_disposition", {})
    disposition_status = disposition.get("status", "UNSPECIFIED")
    disposition_tone = _status_tone(disposition_status)
    self_assessment = metrics.get("self_assessment", {})
    contradictions = metrics.get("contradictions", [])
    dashboard_html = f"""
<section id="dashboard" class="dashboard">
  <div class="dashboard-heading"><div><p class="eyebrow">AUDIT PULSE</p><h2>Repository intelligence</h2><p class="section-lede">A visual readout of the sealed run: scope, evidence, findings, governance and reproducibility.</p></div><span class="dashboard-status {disposition_tone}">{_e(disposition_status + ' · ' + integrity_text)}</span></div>
  <div class="dashboard-grid">
    <div class="coverage-dial" style="--coverage:{(100 * (coverage_summary[0].get('connected_alive_modules', 0) / (coverage_summary[0].get('eligible_source_files', 1) or 1))) if coverage_summary else 0:.2f}%"><div><strong>{_e(f"{coverage_summary[0].get('connected_alive_modules', 0)}/{coverage_summary[0].get('eligible_source_files', 0)}" if coverage_summary else '—')}</strong><span>detector scope</span></div></div>
    <div class="dashboard-panel"><h3>Findings by agent</h3>{_bar_rows(findings_metrics.get('by_agent', {}))}</div>
    <div class="dashboard-panel"><h3>Severity profile</h3>{_bar_rows(findings_metrics.get('by_severity', {}))}</div>
    <div class="dashboard-panel"><h3>Governance skills</h3><div class="mini-stat-grid"><div><strong>{_e(skill_runtime.get('skills_activated', 0))}</strong><span>activated</span></div><div><strong>{_e(skill_runtime.get('skills_not_applicable', 0))}</strong><span>not applicable</span></div><div><strong>{_e(skill_runtime.get('undetermined_skills', 0))}</strong><span>undetermined</span></div></div></div>
  </div>
  <div class="dashboard-panel"><h3>Audit disposition</h3><p><strong>{_e(disposition_status)}</strong> — {_e(disposition.get('reason', 'No disposition recorded.'))}</p><p class="section-lede">Action: {_e(disposition.get('action_required', 'Review the run contract.'))}</p></div>
  <div class="dashboard-panel"><h3>FORGE self assessment</h3><p><strong>{_e(self_assessment.get('specialized_agents', {}).get('available', '—'))}/{_e(self_assessment.get('specialized_agents', {}).get('total', '—'))}</strong> specialized agents · <strong>{_e(len(contradictions))}</strong> contradictions · <strong>{_e(self_assessment.get('limitations', '—'))}</strong> limitations</p><p class="section-lede">Confidence boundary: {_e(self_assessment.get('confidence_boundary', 'not recorded'))}</p></div>
  <div class="metric-strip"><div><strong>{_e(repository_metrics.get('functions', 0))}</strong><span>functions</span></div><div><strong>{_e(repository_metrics.get('loc', {}).get('code', 0))}</strong><span>lines of code</span></div><div><strong>{_e(repository_metrics.get('tests', 0))}</strong><span>tests</span></div><div><strong>{_e(skill_runtime.get('contracts_executed', 0))}</strong><span>contracts executed</span></div><div><strong>{_e(metrics.get('evidence', {}).get('primary_evidence', 0))}</strong><span>primary evidence</span></div>{f'<div class="cost-tile"><strong>{_e(cost.get("credits_consumed"))}</strong><span>credits observed</span></div>' if cost else ''}</div>
  <details class="metrics-details"><summary>Full metrics and audit telemetry</summary><p>Complete machine-readable telemetry is kept in <a href="metrics.json">metrics.json</a>; this report intentionally avoids embedding a second copy of the artifact.</p><div class="detail-grid"><div><h3>Quality</h3><pre>{_e(json.dumps(metrics.get('quality', {}), indent=2, sort_keys=True))}</pre></div><div><h3>Reproducibility</h3><pre>{_e(json.dumps(metrics.get('reproducibility', {}), indent=2, sort_keys=True))}</pre></div></div></details>
</section>"""
    document = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>FORGE report</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
<style>
:root{{
  --bg:#E3B8B8;
  --bg-elevated:#FFFFFF;
  --bg-sunken:#E8E9E3;
  --ink:#1C2222;
  --ink-muted:#5B6460;
  --ink-faint:#8B9490;
  --rule:#D5D6CE;
  --rule-strong:#B9BBB0;
  --accent:#2B5D63;
  --accent-soft:#DCE7E6;
  --ok:#3C7A52; --ok-bg:#DFEDE2; --ok-ink:#2A5A3C;
  --fail:#A8501C; --fail-bg:#F6E3D5; --fail-ink:#7A3A14;
  --serif: "Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,"Times New Roman",serif;
  --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono: "SF Mono","IBM Plex Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --shadow: 0 1px 2px rgba(28,34,34,.08), 0 4px 14px rgba(28,34,34,.06);
}}
*{{box-sizing:border-box;}}
body{{ margin:0; background:var(--bg); color:var(--ink); font-family:var(--sans); font-size:16px; line-height:1.55; -webkit-font-smoothing:antialiased; }}
::selection{{ background:var(--accent-soft); }}
a{{ color:var(--accent); }}
code{{ font-family:var(--mono); }}
.wrap{{ max-width:1100px; margin:0 auto; padding:0 28px 96px; }}
header.masthead{{ border-bottom:2px solid var(--ink); padding:40px 0 22px; margin-bottom:36px; }}
header.masthead h1{{ font-family:var(--serif); font-weight:600; font-size:clamp(26px,4vw,38px); margin:0 0 14px; letter-spacing:.003em; }}
.seal-line{{ display:inline-block; font-family:var(--mono); font-size:13px; letter-spacing:.03em; padding:6px 12px; border-radius:14px; }}
.seal-line.ok{{ background:var(--ok-bg); color:var(--ok-ink); }}
.seal-line.fail{{ background:var(--fail-bg); color:var(--fail-ink); }}
header.masthead p{{ color:var(--ink-muted); font-size:14.5px; max-width:76ch; margin:14px 0 0; }}
header.masthead small{{ display:block; margin-top:6px; color:var(--ink-faint); font-family:var(--mono); font-size:12px; }}
section{{ background:var(--bg-elevated); border:1px solid var(--rule); border-radius:3px; margin:1.5rem 0; padding:22px 24px; box-shadow:var(--shadow); }}
section .section-lede{{ color:var(--ink-muted); font-size:14px; max-width:72ch; margin:8px 0 18px; }}
header.masthead .summary-grid{{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin:24px 0 18px; }}
.stat-tile{{ border:1px solid var(--rule); border-radius:3px; padding:13px 15px; background:var(--bg-sunken); }}
.stat-number{{ font:600 25px var(--serif); }}
.stat-label{{ color:var(--ink-muted); font:11px var(--mono); letter-spacing:.04em; text-transform:uppercase; margin-top:3px; }}
.stat-tile.risk{{ border-top:4px solid var(--fail); }} .stat-tile.caution{{ border-top:4px solid #CDBB78; }}
.stat-tile.safe{{ border-top:4px solid var(--ok); }} .stat-tile.neutral{{ border-top:4px solid var(--accent); }} .stat-tile.muted{{ border-top:4px solid var(--ink-faint); }}
.coverage-hero{{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; padding:16px; background:var(--bg-sunken); border-left:5px solid var(--accent); border-radius:3px; }}
.coverage-hero div{{ background:#fff;border:1px solid var(--rule);padding:12px;border-radius:3px }}.coverage-hero strong,.coverage-hero b,.coverage-hero span{{ display:block }}.coverage-hero strong{{ color:var(--ink-muted);font:11px var(--mono);text-transform:uppercase;letter-spacing:.05em }}.coverage-hero b{{ font:600 24px var(--serif);margin:3px 0 }} .coverage-hero span,.coverage-hero small{{ color:var(--ink-muted);font-size:12px }}.coverage-hero small{{ grid-column:1/-1 }}
section h2{{ font-family:var(--serif); font-size:20px; font-weight:600; margin:0 0 14px; padding-bottom:10px; border-bottom:1px solid var(--rule); }}
#findings h2{{ color:var(--accent); }}
#discarded h2{{ color:#8A6A2E; }}
#scope h2{{ color:var(--fail-ink); }}
.finding,.discarded,.scope{{ border:1px solid var(--rule); border-radius:3px; padding:14px 18px; margin:14px 0; background:var(--bg); }}
.finding-toolbar{{ display:flex; flex-wrap:wrap; gap:10px; align-items:end; padding:12px; margin:0 0 16px; background:var(--bg-sunken); border:1px solid var(--rule); border-radius:3px; }}
.finding-toolbar label{{ display:flex; flex-direction:column; gap:4px; font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--ink-muted); }}
.finding-toolbar input,.finding-toolbar select{{ min-width:150px; padding:7px 9px; border:1px solid var(--rule-strong); border-radius:3px; background:var(--bg-elevated); color:var(--ink); font:13px var(--sans); text-transform:none; letter-spacing:normal; }}
.finding-toolbar input:focus,.finding-toolbar select:focus{{ outline:2px solid var(--accent); outline-offset:1px; }}
.filter-count{{ margin-left:auto; padding:8px 0; font-family:var(--mono); font-size:12px; color:var(--ink-muted); }}
.finding.is-hidden{{ display:none; }}
.severity-card-critical{{ border-left:6px solid #A8501C; }}
.severity-card-high{{ border-left:6px solid #D89A70; }}
.severity-card-medium{{ border-left:6px solid #CDBB78; }}
.severity-card-low,.severity-card-info{{ border-left:6px solid #9BB8A2; }}
.finding p,.discarded p,.scope p{{ margin:6px 0; font-size:14px; }}
.badge{{ font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase; background:var(--accent-soft); color:var(--accent); border:1px solid var(--rule-strong); padding:3px 9px; border-radius:11px; }}
.severity-critical{{ background:#F6D7D5; color:#8E2420; border-color:#C76C67; }}
.severity-high{{ background:#F6E3D5; color:#7A3A14; border-color:#D89A70; }}
.severity-medium{{ background:#F4EED8; color:#765D1C; border-color:#CDBB78; }}
.severity-low,.severity-info{{ background:#E5EDE7; color:#356045; border-color:#9BB8A2; }}
.ref{{ font-family:var(--mono); font-size:12.5px; color:var(--ink-muted); }}
.finding code{{ display:block; white-space:pre-wrap; background:var(--bg-sunken); padding:.6rem; border-radius:3px; font-size:13px; margin-top:4px; }}
small{{ color:var(--ink-faint); }}
table.data-table{{ border-collapse:collapse; width:100%; }}
table.data-table td,table.data-table th{{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--rule); font-size:13.5px; vertical-align:top; }}
table.data-table th{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted); background:var(--bg-sunken); }}
table.data-table tr:last-child td{{ border-bottom:none; }}
table.data-table td:first-child{{ font-family:var(--mono); font-size:12.5px; white-space:nowrap; }}
.chain-block{{ font-family:var(--mono); font-size:13px; background:var(--bg-sunken); padding:14px 18px; border-radius:3px; white-space:pre-wrap; }}
.dashboard{{ background:linear-gradient(135deg,#fff 0%,#fff 62%,#F8E9E9 100%); overflow:hidden; }}
.dashboard-heading{{ display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }}
.eyebrow{{ color:var(--accent); font:11px var(--mono); letter-spacing:.14em; margin:0 0 4px; }}
.dashboard-heading h2{{ margin-top:0; }}
.dashboard-status{{ border:1px solid var(--rule-strong); background:var(--bg-sunken); color:var(--ink-muted); border-radius:999px; padding:7px 12px; font:11px var(--mono); white-space:nowrap; }} .dashboard-status.ok{{ border-color:#A9C9B0; background:#EDF7EF; color:#2A5A3C; }} .dashboard-status.partial{{ border-color:#D89A70; background:#FFF4E9; color:#7A3A14; }} .dashboard-status.fail{{ border-color:#D39A9A; background:#F8E5E5; color:#8B2F2F; }}
.dashboard-grid{{ display:grid; grid-template-columns:150px repeat(3,minmax(0,1fr)); gap:14px; align-items:stretch; }}
.coverage-dial{{ width:128px; height:128px; margin:8px auto; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--accent) var(--coverage),#F1DADA 0); position:relative; }}
.coverage-dial::after{{ content:""; position:absolute; inset:10px; border-radius:50%; background:var(--bg-elevated); }}
.coverage-dial div{{ position:relative; z-index:1; text-align:center; }}
.coverage-dial strong{{ display:block; font:600 25px var(--serif); }} .coverage-dial span{{ color:var(--ink-muted); font:10px var(--mono); text-transform:uppercase; }}
.dashboard-panel{{ background:rgba(232,233,227,.48); border:1px solid var(--rule); border-radius:4px; padding:15px; }}
.dashboard-panel h3{{ margin:0 0 13px; font-size:16px; }}
.bar-row{{ display:grid; grid-template-columns:minmax(76px,1fr) 1.4fr 24px; gap:8px; align-items:center; margin:9px 0; }}
.bar-label,.bar-value{{ font:11px var(--mono); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }} .bar-value{{ text-align:right; }}
.bar-track{{ height:7px; background:#F1DADA; border-radius:99px; overflow:hidden; }} .bar-fill{{ display:block; height:100%; background:linear-gradient(90deg,var(--accent),#87AEB0); border-radius:99px; }}
.mini-stat-grid{{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }} .mini-stat-grid div{{ background:#fff; border:1px solid var(--rule); border-radius:3px; padding:10px 8px; }} .mini-stat-grid strong,.mini-stat-grid span,.metric-strip strong,.metric-strip span{{ display:block; }} .mini-stat-grid strong{{ font:600 22px var(--serif); }} .mini-stat-grid span,.metric-strip span{{ color:var(--ink-muted); font:10px var(--mono); text-transform:uppercase; }}
.metric-strip{{ display:grid; grid-template-columns:repeat(5,1fr); gap:1px; margin-top:16px; border:1px solid var(--rule); background:var(--rule); }} .metric-strip div{{ background:#fff; padding:13px 15px; }} .metric-strip strong{{ font:600 22px var(--serif); }}
.metric-strip .cost-tile{{ background:#FFF4E9; border-top:4px solid #D89A70; }}
.metrics-details{{ margin-top:16px; border-top:1px solid var(--rule); padding-top:13px; }} .metrics-details summary{{ cursor:pointer; color:var(--accent); font:12px var(--mono); }} .detail-grid{{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin-top:14px; }} .detail-grid h3{{ font-size:14px; }} .detail-grid pre{{ max-height:260px; overflow:auto; }} .empty-state{{ color:var(--ink-muted); font-size:13px; }}
@media(max-width:900px){{ .dashboard-grid{{ grid-template-columns:1fr 1fr; }} .coverage-dial{{ grid-column:span 2; }} }} @media(max-width:620px){{ .dashboard-heading{{ display:block; }} .dashboard-status{{ display:inline-block; margin:8px 0 16px; }} .dashboard-grid,.detail-grid,.coverage-hero{{ grid-template-columns:1fr; }} .coverage-dial{{ grid-column:auto; }} .metric-strip{{ grid-template-columns:repeat(2,1fr); }} }}
</style></head><body>
<div class=\"wrap\">
<header class=\"masthead\">
  <h1>FORGE verification report</h1>
  <span class=\"seal-line {seal_class}\">{_e(seal_text)}</span>
  <div class=\"summary-grid\">{summary_tiles_html}</div>
  {('<section id="agent-metrics"><h2>Agent metrics</h2><ul>' + metrics_html + '</ul></section>') if metrics else ''}
  <table class=\"data-table\">{info_table_html}</table>
</header>

<section id=\"objective\"><h2>Objective</h2>{objective_html}</section>
{dashboard_html}

<section id=\"findings\"><h2>FINDINGS</h2>{filter_html}{findings_html}</section>
<section id=\"discarded\"><h2>DISCARDED</h2><p>Generated hypotheses ruled out by the verification criteria are retained here with their reasons.</p>{discarded_html}</section>
<section id=\"clean\"><h2>No structural risk indicators found</h2><p>Audited modules with zero surviving findings:</p><ul>{clean_html}</ul></section>
<section id=\"scope\"><h2>NOT ANALYZED</h2><p>These triaged modules were not analyzed in this run because they were not classified as CONNECTED_ALIVE:</p>{scope_html}</section>

<section id=\"hypotheses-summary\"><h2>Hypotheses summary</h2>{hypotheses_summary_html}</section>

<section id=\"decision\"><h2>Decision</h2><p><strong>{_e(seal_text)}</strong></p><p>{limitations}</p><p><small>{_e(git_note)}</small></p></section>

<section id=\"quality\"><h2>Quality metrics</h2><table class=\"data-table\">{quality_table_html}</table></section>
{coverage_section_html}
<section id=\"limitations\"><h2>Honest degradation and limitations</h2><ul>{degradation_html}</ul></section>

<section id=\"chain-of-custody\"><h2>Chain of custody</h2><div class=\"chain-block\">entry_hash : {_e(last_hash)}\nchain_ok   : {_e(seal["ok"])}</div></section>
</div>
<script>
(() => {{
  const cards = [...document.querySelectorAll('.finding')];
  const search = document.getElementById('finding-search');
  const agent = document.getElementById('finding-agent');
  const severity = document.getElementById('finding-severity');
  const epistemic = document.getElementById('finding-epistemic');
  const count = document.getElementById('finding-count');
  const apply = () => {{
    const query = (search.value || '').trim().toLowerCase();
    let visible = 0;
    cards.forEach(card => {{
      const matches = (!agent.value || card.dataset.agent === agent.value)
        && (!severity.value || card.dataset.severity === severity.value)
        && (!epistemic.value || card.dataset.epistemic === epistemic.value)
        && (!query || card.dataset.search.includes(query));
      card.classList.toggle('is-hidden', !matches);
      if (matches) visible += 1;
    }});
    count.textContent = `Showing ${{visible}} of ${{cards.length}}`;
  }};
  [search, agent, severity, epistemic].forEach(control => control.addEventListener('input', apply));
}})();
</script>
</body></html>"""
    Path(destination).write_text(document, encoding="utf-8")
