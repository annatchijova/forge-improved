"""Automatic presentation of a completed FORGE run.

JSON artifacts remain canonical. This module is the single convenience entry
point for turning a run directory into the visual dashboard and all report
tiers without requiring a second manual command.
"""
from __future__ import annotations

import json
import html
from pathlib import Path
from typing import Any

from forge.report import render_report
from forge.tiered_report import render_tiered_report


REPORT_MODES = ("summary", "standard", "extended", "json")


def render_sharded_dashboard(run_dir: str | Path, destination: str | Path | None = None) -> Path:
    """Render a presentation-only index for a bounded, independently sealed run.

    Sharding deliberately does not create a parent seal.  This index therefore
    links to each shard's own verified report and labels the aggregate as a
    navigation view, never as a new finding set.
    """
    directory = Path(run_dir)
    plan_path = directory / "shards.json"
    if not plan_path.is_file():
        raise FileNotFoundError(f"sharded run manifest not found: {plan_path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    cards = []
    total_rows = total_discarded = 0
    finding_hashes: set[str] = set()
    for item in plan.get("shards", []):
        index = int(item.get("index", len(cards) + 1))
        shard_dir = directory / "shards" / f"shard-{index:04d}"
        metrics = {}
        metrics_path = shard_dir / "metrics.json"
        if metrics_path.is_file():
            try:
                metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                metrics = {}
        finding_records = []
        findings_path = shard_dir / "findings.jsonl"
        if findings_path.is_file():
            for line in findings_path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                    finding_records.append(record)
                    if record.get("hash"):
                        finding_hashes.add(str(record["hash"]))
                except (ValueError, json.JSONDecodeError):
                    continue
        findings = int(item.get("findings", metrics.get("findings", {}).get("total", 0)) or 0)
        discarded = int(item.get("discarded", 0) or 0)
        total_rows += findings
        total_discarded += discarded
        status = str(item.get("status", "UNKNOWN"))
        tone = "ok" if status == "COMPLETE" else ("partial" if status.startswith(("ABSTAIN", "PARTIAL")) else "fail")
        report_name = "forge-report-standard.html" if (shard_dir / "forge-report-standard.html").is_file() else "report.md"
        report_href = f"shards/shard-{index:04d}/{report_name}"
        cards.append(
            f"<article class='shard-card'><div class='shard-top'><span>SHARD {index:04d}</span>"
            f"<b class='{tone}'>{html.escape(status)}</b></div>"
            f"<strong>{findings}</strong><span>surviving leads</span>"
            f"<p>{discarded} discarded hypotheses · {len(item.get('paths', []))} connected modules</p>"
            f"<a class='button' href='{html.escape(report_href)}'>Open shard report</a> "
            f"<a href='shards/shard-{index:04d}/forge-report-summary.html'>summary</a></article>"
        )
    destination = Path(destination) if destination else directory / "forge-report-shards.html"
    unique_findings = len(finding_hashes) if finding_hashes else total_rows
    document = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>FORGE sharded audit</title>
<style>:root{{--ink:#172326;--muted:#5d6b6d;--paper:#fff;--wash:#f3f7f6;--line:#d7e1df;--accent:#176b70;--ok:#2d7a4c;--fail:#a23d36;--partial:#9a6b18;--mono:ui-monospace,SFMono-Regular,Menlo,monospace;--serif:Georgia,serif}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--wash);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}main{{max-width:1080px;margin:auto;padding:40px 24px 72px}}header{{border-bottom:2px solid var(--ink);padding-bottom:22px;margin-bottom:25px}}h1{{font:600 clamp(30px,5vw,48px) var(--serif);margin:0 0 10px}}h2{{font:600 22px var(--serif)}}.eyebrow,.shard-top{{font:11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}}.notice{{border-left:5px solid #b27620;background:#fff8ea;padding:15px 18px;margin:20px 0}}.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}}.stat,.shard-card{{background:var(--paper);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:0 5px 18px #1723260d}}.stat strong{{display:block;font:600 30px var(--serif)}}.stat span,.stat small,.shard-card>span{{color:var(--muted);font-size:13px;display:block}}.stat small{{font-family:var(--mono);margin-top:5px;font-size:11px}}.shards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}}.shard-top{{display:flex;justify-content:space-between;margin-bottom:18px}}.shard-top b{{color:var(--ok)}}.shard-top b.partial{{color:var(--partial)}}.shard-top b.fail{{color:var(--fail)}}.shard-card>strong{{display:block;font:600 32px var(--serif)}}.shard-card p{{color:var(--muted);font-size:13px;min-height:40px}}a{{color:var(--accent)}}.button{{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;border-radius:5px;padding:8px 11px;font-size:13px}}footer{{margin-top:30px;color:var(--muted);font:12px var(--mono)}}@media(max-width:600px){{.stats{{grid-template-columns:1fr}}main{{padding:25px 15px 50px}}}}</style></head>
<body><main><header><p class='eyebrow'>FORGE · PRESENTATION INDEX</p><h1>Sharded audit review</h1>
<p>Each shard has an independent sealed evidence chain. This page is navigation and aggregation only; it does not create a parent seal or merge findings.</p></header>
<div class='notice'><strong>Qualified result:</strong> {html.escape(str(plan.get('status','UNKNOWN')))} · {html.escape(str(plan.get('parent_seal','')))}</div>
<div class='stats'><div class='stat'><strong>{unique_findings}</strong><span>unique surviving leads by record hash</span><small>{total_rows} shard rows before deduplication</small></div><div class='stat'><strong>{total_discarded}</strong><span>discarded hypotheses</span></div><div class='stat'><strong>{len(cards)}</strong><span>independently sealed shards</span></div></div>
<h2>Open a shard</h2><div class='shards'>{''.join(cards) or '<p>No shard records were found.</p>'}</div>
<footer>Repository: {html.escape(str(plan.get('repository','unknown')))} · max connected per shard: {html.escape(str(plan.get('max_connected','unknown')))}</footer>
</main></body></html>"""
    destination.write_text(document, encoding="utf-8")
    return destination


def render_dashboard(run_dir: str | Path, modes: tuple[str, ...] = REPORT_MODES) -> dict[str, str]:
    """Render the dashboard and requested tiers for an existing run directory.

    The sealed manifest and JSON sidecars are read-only inputs. The function
    returns the generated paths and never touches the audited repository.
    """
    directory = Path(run_dir)
    required = {
        "triage": directory / "triage-manifest.json",
        "hypotheses": directory / "hypotheses-manifest.json",
        "sealed": directory / "verification-manifest.sealed.json",
        "coverage": directory / "coverage-report.json",
        "metrics": directory / "metrics.json",
    }
    missing = [str(path) for path in required.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("incomplete FORGE run; missing: " + ", ".join(missing))
    invalid = [mode for mode in modes if mode not in REPORT_MODES]
    if invalid:
        raise ValueError(f"unsupported report mode(s): {', '.join(invalid)}")

    paths: dict[str, str] = {}
    main = directory / "forge-report.html"
    render_report(required["triage"], required["hypotheses"], required["sealed"], main, required["coverage"], json.loads(required["metrics"].read_text()))
    paths["report"] = str(main)
    for mode in modes:
        output = directory / f"forge-report-{mode}.{'json' if mode == 'json' else 'html'}"
        render_tiered_report(required["sealed"], mode, output)
        paths[f"report_{mode}"] = str(output)
    return paths


__all__ = ("REPORT_MODES", "render_dashboard", "render_sharded_dashboard")
