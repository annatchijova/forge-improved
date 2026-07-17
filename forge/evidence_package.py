"""Human- and machine-readable evidence-package sidecars."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def _source_commit(repository: str, finding: dict[str, Any]) -> str | None:
    """Return the exact source commit when the repository supports git blame."""
    source = next((item for item in finding.get("evidence", []) if item.get("kind") == "source"), None)
    if not source:
        return None
    module, separator, line_text = "", "", ""
    try:
        module, line_text = str(source.get("source", "")).rsplit(":", 1)
        separator = ":"
    except ValueError:
        pass
    if not separator or not module:
        return None
    try:
        line = int(line_text)
        raw = subprocess.check_output(
            ["git", "-C", repository, "blame", "--line-porcelain", "-L", f"{line},{line}", "--", module],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    first = raw.splitlines()[0].split() if raw.splitlines() else []
    return first[0] if first else None


def build_repository_profile(*, root: str, triage: Any, governance: Any, coverage: Any,
                             metrics: dict[str, Any], findings: list[Any],
                             elapsed_seconds: float) -> dict[str, Any]:
    """Build a compact profile from already-collected audit evidence."""
    return {
        "profile_schema_version": "1.0",
        "repository": root,
        "languages": triage.to_dict().get("stacks", []),
        "module_summary": triage.summary,
        "modules": len(triage.modules),
        "connected_modules": sum(item.module_class.value == "CONNECTED_ALIVE" for item in triage.modules),
        "domains": sorted({domain for item in governance.hypotheses for domain in item.domains}),
        "skills": {
            "loaded": sorted(metrics.get("reproducibility", {}).get("skill_versions", {}).keys()),
            "activated": metrics.get("skill_runtime", {}).get("skills_activated", 0),
            "undetermined": metrics.get("skill_runtime", {}).get("undetermined_skills", 0),
        },
        "findings": {
            "total": len(findings),
            "by_agent": metrics.get("findings", {}).get("by_agent", {}),
            "by_severity": metrics.get("findings", {}).get("by_severity", {}),
        },
        "coverage": coverage.to_dict(),
        "confidence": {
            "discarded_hypotheses": metrics.get("findings", {}).get("discarded_hypotheses", 0),
            "limitations": len(metrics.get("honest_degradation", {}).get("limitations", [])),
        },
        "audit_duration_seconds": round(elapsed_seconds, 6),
        "note": "Profile summarizes observed audit artifacts; it is not an invented repository quality score.",
    }


def write_repository_profile(profile: dict[str, Any], destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown_report(*, sealed: dict[str, Any], metrics: dict[str, Any], profile: dict[str, Any],
                          destination: str | Path) -> None:
    manifest = sealed.get("manifest", {})
    findings = [entry.get("finding", {}) for entry in sealed.get("chain", [])]
    coverage = profile.get("coverage", {})
    ratio = coverage.get("coverage_ratio", {})
    denominator = ratio.get("denominator", 0)
    percent = (100 * ratio.get("numerator", 0) / denominator) if denominator else 0
    lines = [
        "# FORGE audit report",
        "",
        f"Repository: `{profile.get('repository', 'unknown')}`",
        f"Seal: **{'VERIFIED' if sealed.get('chain') is not None else 'UNKNOWN'}**",
        f"Findings: **{len(findings)}** · Discarded hypotheses: **{len(manifest.get('discarded', []))}**",
        f"Finding-set digest: `{manifest.get('finding_set_digest', metrics.get('findings', {}).get('finding_digest', 'unavailable'))}`",
        f"Eligible source coverage: **{ratio.get('numerator', 0)}/{denominator} ({percent:.1f}%)**",
        f"Discovery accounting: **{coverage.get('files_analyzed', 0)}/{coverage.get('files_discovered', 0)} discovered files**",
        f"Audit disposition: **{metrics.get('audit_disposition', {}).get('status', 'UNSPECIFIED')}**",
        "",
        "## Repository profile",
        "",
        f"- Modules: {profile.get('modules', 0)} ({profile.get('connected_modules', 0)} connected)",
        f"- Domains: {', '.join(profile.get('domains', [])) or 'none inferred'}",
        f"- Audit duration: {profile.get('audit_duration_seconds', 0)} seconds",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            commit = _source_commit(profile.get("repository", ""), finding)
            lines.extend([
                f"### {finding.get('severity', 'MEDIUM')} · {finding.get('module_path', 'unknown')}",
                f"- Agent: `{finding.get('agent', 'unknown')}`",
                f"- Status: `{finding.get('epistemic_level', 'unknown')}`",
                f"- Description: {finding.get('description', '')}",
                f"- Reasoning: {finding.get('reasoning', '')}",
                f"- Source commit: `{commit}`" if commit else "- Source commit: unavailable (source evidence retained)",
                "",
            ])
    else:
        lines.append("No surviving findings in the sealed manifest.")
        lines.append("")
    lines.extend(["## Limitations", ""])
    limitations = metrics.get("honest_degradation", {}).get("limitations", [])
    lines.extend(f"- {item}" for item in limitations) if limitations else lines.append("- None recorded.")
    lines.append("")
    Path(destination).write_text("\n".join(lines), encoding="utf-8")
