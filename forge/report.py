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

from forge.sealing import verify_sealed


def _e(value: Any) -> str:
    return html.escape(str(value))


def _load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


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
    return f"""<article class=\"finding\">
      <p><strong>Agent:</strong> {_e(finding.get('agent', 'bug_investigator'))}</p>
      <div><span class=\"badge\">{_e(finding.get('epistemic_level', ''))}</span> <span class=\"ref\">{_e(source_ref)}</span></div>
      <p><strong>Description (inference):</strong> {_e(finding.get('description', ''))}</p>
      <p><strong>Source observation:</strong> <code>{_e(source.get('detail', ''))}</code></p>
      <p><strong>Reasoning:</strong> {_e(finding.get('reasoning', ''))}</p>
      <p><strong>Falsification test:</strong> {_e(falsifier)}</p>
      <p><strong>Additional evidence — git blame:</strong> {_e(blame_html)}</p>
    </article>"""


def render_report(triage_path: str | Path, hypotheses_path: str | Path, sealed_path: str | Path, destination: str | Path, coverage_path: str | Path | None = None, metrics: dict[str, Any] | None = None) -> None:
    triage = _load(triage_path)
    hypotheses_doc = _load(hypotheses_path)
    sealed = _load(sealed_path)
    coverage = _load(coverage_path) if coverage_path else None
    metrics = metrics or {}
    seal = verify_sealed(sealed)
    manifest = sealed.get("manifest", {})
    findings = [entry.get("finding", {}) for entry in sealed.get("chain", [])]
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
    if coverage:
        ratio = coverage.get("coverage_ratio", {})
        ratio_text = f"{ratio.get('numerator', 0)}/{ratio.get('denominator', 1)}"
        info_rows = [("Coverage", f"discovered={coverage.get('files_discovered', 0)}, analyzed={coverage.get('files_analyzed', 0)}, skipped={coverage.get('files_skipped', 0)}, ratio={ratio_text}"), *info_rows]
    # The detailed layered metrics are persisted as metrics.json. Keep the
    # HTML agent panel compact and route only the legacy per-agent accounting
    # through the examination-aware renderer; otherwise nested dictionaries
    # would reintroduce the large raw examination dump this panel avoids.
    display_metrics = metrics.get("agent_metrics", metrics)
    metrics_html = "".join(_metric_block(agent, values) for agent, values in display_metrics.items())
    info_table_html = "".join(f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in info_rows)

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
    quality_metrics = metrics.get("quality", {})
    contract_ratio = quality_metrics.get("contract_coverage", {})
    if contract_ratio:
        quality_rows.append(("Contract coverage", f"{_e(contract_ratio.get('covered', 0))}/{_e(contract_ratio.get('total', 0))} — {_e(quality_metrics.get('contract_coverage_note', 'context unavailable'))}"))
    quality_table_html = "".join(f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in quality_rows)
    document = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>FORGE report</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
<style>
:root{{
  --bg:#E3B8B8;
  --bg-elevated:#FFFFFF;
  --bg-sunken:#D9A9A9;
  --ink:#1C2222;
  --ink-muted:#5B6460;
  --ink-faint:#8B9490;
  --rule:#C99E9E;
  --rule-strong:#B98888;
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
section h2{{ font-family:var(--serif); font-size:20px; font-weight:600; margin:0 0 14px; padding-bottom:10px; border-bottom:1px solid var(--rule); }}
#findings h2{{ color:var(--accent); }}
#discarded h2{{ color:#8A6A2E; }}
#scope h2{{ color:var(--fail-ink); }}
.finding,.discarded,.scope{{ border:1px solid var(--rule); border-radius:3px; padding:14px 18px; margin:14px 0; background:var(--bg); }}
.finding p,.discarded p,.scope p{{ margin:6px 0; font-size:14px; }}
.badge{{ font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase; background:var(--accent-soft); color:var(--accent); border:1px solid var(--rule-strong); padding:3px 9px; border-radius:11px; }}
.ref{{ font-family:var(--mono); font-size:12.5px; color:var(--ink-muted); }}
.finding code{{ display:block; white-space:pre-wrap; background:var(--bg-sunken); padding:.6rem; border-radius:3px; font-size:13px; margin-top:4px; }}
small{{ color:var(--ink-faint); }}
table.data-table{{ border-collapse:collapse; width:100%; }}
table.data-table td,table.data-table th{{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--rule); font-size:13.5px; vertical-align:top; }}
table.data-table th{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted); background:var(--bg-sunken); }}
table.data-table tr:last-child td{{ border-bottom:none; }}
table.data-table td:first-child{{ font-family:var(--mono); font-size:12.5px; white-space:nowrap; }}
.chain-block{{ font-family:var(--mono); font-size:13px; background:var(--bg-sunken); padding:14px 18px; border-radius:3px; white-space:pre-wrap; }}
</style></head><body>
<div class=\"wrap\">
<header class=\"masthead\">
  <h1>FORGE verification report</h1>
  {('<section id="coverage"><h2>Coverage</h2><p>Files discovered: ' + _e(coverage.get('files_discovered')) + ' · analyzed: ' + _e(coverage.get('files_analyzed')) + ' · skipped: ' + _e(coverage.get('files_skipped')) + '</p><p>Skipped reasons: ' + _e(coverage.get('skipped_reasons', {})) + '</p></section>') if coverage else ''}
  <span class=\"seal-line {seal_class}\">{_e(seal_text)}</span>
  {('<section id="agent-metrics"><h2>Agent metrics</h2><ul>' + metrics_html + '</ul></section>') if metrics else ''}
  <table class=\"data-table\">{info_table_html}</table>
</header>

<section id=\"objective\"><h2>Objective</h2>{objective_html}</section>

<section id=\"findings\"><h2>FINDINGS</h2>{findings_html}</section>
<section id=\"discarded\"><h2>DISCARDED</h2><p>Generated hypotheses ruled out by the verification criteria are retained here with their reasons.</p>{discarded_html}</section>
<section id=\"clean\"><h2>No structural risk indicators found</h2><p>Audited modules with zero surviving findings:</p><ul>{clean_html}</ul></section>
<section id=\"scope\"><h2>NOT ANALYZED</h2><p>These triaged modules were not analyzed in this run because they were not classified as CONNECTED_ALIVE:</p>{scope_html}</section>

<section id=\"hypotheses-summary\"><h2>Hypotheses summary</h2>{hypotheses_summary_html}</section>

<section id=\"decision\"><h2>Decision</h2><p><strong>{_e(seal_text)}</strong></p><p>{limitations}</p><p><small>{_e(git_note)}</small></p></section>

<section id=\"quality\"><h2>Quality metrics</h2><table class=\"data-table\">{quality_table_html}</table></section>

<section id=\"chain-of-custody\"><h2>Chain of custody</h2><div class=\"chain-block\">entry_hash : {_e(last_hash)}\nchain_ok   : {_e(seal["ok"])}</div></section>
</div>
</body></html>"""
    Path(destination).write_text(document, encoding="utf-8")
