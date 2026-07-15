"""Automatic presentation of a completed FORGE run.

JSON artifacts remain canonical. This module is the single convenience entry
point for turning a run directory into the visual dashboard and all report
tiers without requiring a second manual command.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forge.report import render_report
from forge.tiered_report import render_tiered_report


REPORT_MODES = ("summary", "standard", "extended", "json")


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


__all__ = ("REPORT_MODES", "render_dashboard")
