"""Presentation-only tiers over an existing sealed FORGE artifact."""
from __future__ import annotations
import base64
import html
import json
from pathlib import Path
from typing import Any

from forge.sealing import verify_sealed
from forge.io import load_json

MODES = ("summary", "standard", "extended", "json")

def _load(path: Path) -> dict[str, Any]:
    return load_json(path, f"report artifact {path}")

def findings_from_sealed(sealed: dict[str, Any]) -> list[dict[str, Any]]:
    """The sole finding source for every tier; never recomputed by rendering."""
    return [entry.get("finding", {}) for entry in sealed.get("chain", [])]

def canonical_findings_bytes(findings: list[dict[str, Any]]) -> bytes:
    return json.dumps(findings, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _sidecar(sealed_path: Path, name: str) -> dict[str, Any] | None:
    candidate = sealed_path.parent / name
    try: return _load(candidate)
    except (OSError, json.JSONDecodeError): return None

def _per_module_coverage(sealed_path: Path) -> dict[str, Any] | None:
    triage = _sidecar(sealed_path, "triage-manifest.json")
    coverage = _sidecar(sealed_path, "coverage-report.json")
    if not triage and not coverage: return None
    modules = {item.get("path", "unknown"): {"triage": item.get("module_class", "unknown")} for item in (triage or {}).get("modules", [])}
    for reason, paths in (coverage or {}).get("skipped_reasons", {}).items():
        for path in paths:
            modules.setdefault(path, {})["coverage"] = reason
    return dict(sorted(modules.items()))

def _finding_html(finding: dict[str, Any], extended: bool) -> str:
    evidence = finding.get("evidence", [])
    primary = evidence[0] if evidence else {}
    body = [
        f"<h3>{html.escape(str(finding.get('module_path', 'unknown')))}</h3>",
        f"<p>Agent: {html.escape(str(finding.get('agent', 'bug_investigator')))} · Severity: {html.escape(str(finding.get('severity', 'MEDIUM')))} · Category: {html.escape(str(finding.get('category', '')))} · Outcome: {html.escape(str(finding.get('outcome', 'OBSERVED')))}</p>",
        f"<p>{html.escape(str(finding.get('description', '')))}</p>",
        f"<pre>{html.escape(str(primary.get('source', '')))}: {html.escape(str(primary.get('detail', '')))}</pre>",
    ]
    if extended:
        body.append(f"<details open><summary>Reasoning chain</summary><pre>{html.escape(str(finding.get('reasoning', '')))}</pre><pre>{html.escape(json.dumps(evidence, indent=2, sort_keys=True))}</pre></details>")
    return "<article class='finding'>" + "".join(body) + "</article>"

def render_tiered_report(sealed_path: str | Path, mode: str, destination: str | Path | None = None) -> Path:
    if mode not in MODES: raise ValueError(f"unsupported report mode: {mode}")
    source = Path(sealed_path)
    destination = Path(destination) if destination else source.with_name(f"{source.stem}.{mode}" + (".json" if mode == "json" else ".html"))
    if mode == "json":
        # This is deliberately the original structured artifact, not a projection.
        destination.write_bytes(source.read_bytes())
        return destination
    sealed = _load(source); findings = findings_from_sealed(sealed); verification = verify_sealed(sealed)
    manifest = sealed.get("manifest", {}); payload = base64.b64encode(canonical_findings_bytes(findings)).decode("ascii")
    seal_text = "VERIFIED" if verification.get("ok") else "FAILED: " + "; ".join(verification.get("issues", []))
    sections = [
        "<section id='seal'><h2>Seal status</h2><p>" + seal_text + "</p></section>",
        "<section id='findings'><h2>Findings</h2>" + "".join(_finding_html(f, mode == "extended") for f in findings) + "</section>",
        "<section id='limitations'><h2>Limitations</h2><ul>" + "".join(f"<li>{x}</li>" for x in sealed.get("limitations", [])) + "</ul></section>",
    ]
    if mode in {"standard", "extended"}:
        discarded = manifest.get("discarded", [])
        coverage = _per_module_coverage(source)
        sections += ["<section id='discarded'><h2>Discarded hypotheses</h2><pre>" + json.dumps(discarded, indent=2, sort_keys=True) + "</pre></section>",
                     "<section id='coverage'><h2>Per-module coverage</h2><pre>" + (json.dumps(coverage, indent=2, sort_keys=True) if coverage else "Triage/coverage sidecars unavailable") + "</pre></section>"]
    if mode == "extended":
        skills = _sidecar(source, "skills-runtime.json")
        sections += ["<section id='contracts'><h2>Contract evaluations and governance applicability</h2><pre>" + (json.dumps(skills, indent=2, sort_keys=True) if skills else "Skill runtime sidecar unavailable") + "</pre></section>",
                     "<section id='trace'><h2>Metrics and audit trace</h2><pre>" + json.dumps({"manifest": manifest, "chain": sealed.get("chain", []), "audit_trace": sealed.get("audit_trace", "Audit trace unavailable")}, indent=2, sort_keys=True) + "</pre></section>"]
    # Keep the tiered renderer on the same visual identity as the primary
    # FORGE renderer.  In particular, never fall back to the browser's white
    # canvas: reports are often presented directly to reviewers or judges.
    style = """
<style>
:root{--bg:#E3B8B8;--bg-elevated:#FFFFFF;--bg-sunken:#E8E9E3;--ink:#1C2222;--ink-muted:#5B6460;--rule:#D5D6CE;--accent:#2B5D63;--ok:#3C7A52;--fail:#A8501C;--serif:Georgia,"Times New Roman",serif;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--sans);-webkit-font-smoothing:antialiased}.wrap{max-width:1180px;margin:0 auto;padding:0 24px 56px}header{border-bottom:2px solid var(--ink);padding:40px 0 22px;margin-bottom:36px}h1{font:600 clamp(28px,4vw,40px) var(--serif);margin:0 0 18px}h2{font:600 21px var(--serif);color:var(--accent);border-bottom:1px solid var(--rule);padding-bottom:10px}h3{font:600 17px var(--serif);margin-bottom:6px}section{background:var(--bg-elevated);border:1px solid var(--rule);border-radius:3px;margin:24px 0;padding:22px 24px;box-shadow:0 4px 14px rgba(28,34,34,.06)}#seal p{display:inline-block;background:#DFEDE2;color:#2A5A3C;border-radius:14px;padding:6px 12px;font:12px var(--mono);letter-spacing:.04em}.finding{background:var(--bg);border:1px solid var(--rule);border-left:4px solid var(--accent);border-radius:3px;padding:14px 18px;margin:14px 0}.finding p:first-of-type{color:var(--ink-muted);font:12px var(--mono)}pre{background:var(--bg-sunken);border-radius:3px;padding:12px 14px;overflow:auto;white-space:pre-wrap;font:13px/1.5 var(--mono)}#limitations h2,#discarded h2{color:var(--fail)}
</style>
"""
    document = "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>FORGE " + mode + " report</title>" + style + "</head><body><div class='wrap'><header><h1>FORGE " + mode + " report</h1></header>" + "".join(sections) + f"<meta id='forge-findings' data-canonical-base64='{payload}'></div></body></html>"
    destination.write_text(document, encoding="utf-8")
    return destination

def rendered_finding_bytes(path: str | Path, mode: str) -> bytes:
    """Test/consumer helper proving the renderer preserved the sealed finding set."""
    raw = Path(path).read_bytes()
    if mode == "json": return canonical_findings_bytes(findings_from_sealed(load_json(path, f"report artifact {path}")))
    marker = b"data-canonical-base64='"; encoded = raw.split(marker, 1)[1].split(b"'", 1)[0]
    return base64.b64decode(encoded)
