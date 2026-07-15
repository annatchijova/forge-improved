"""Sequential, bounded orchestration of the FORGE evidence pipeline."""
from __future__ import annotations

import argparse
import json
import ast
import time
from fractions import Fraction
from pathlib import Path
from typing import Any

from forge.detector.stack import triage, write_manifest
from forge.hypotheses import generate_hypotheses, write_hypotheses_manifest
from forge.report import render_report
from forge.sealing import write_sealed_manifest
from forge.verification import verify_hypotheses, write_verification_manifest
from forge.agents import archaeologist, bug_investigator, security_auditor, integrity_inspector, report_composer
from forge.models import CoverageReport, Evidence, Finding, VerificationManifest
from forge.detector.stack import SKIP_DIRS, discover_files

def _coverage(root: Path, families=()) -> CoverageReport:
    discovered = discover_files(root, include_excluded=True)
    skipped: dict[str, list[str]] = {"excluded_by_policy": [], "syntax_error": [], "binary_or_unreadable": [], "non_python_not_analyzed": []}
    analyzed = 0
    for p in discovered:
        rel = str(p.relative_to(root))
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            skipped["excluded_by_policy"].append(rel); continue
        try: source = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            skipped["binary_or_unreadable"].append(rel); continue
        if p.suffix != ".py":
            skipped["non_python_not_analyzed"].append(rel); continue
        try: ast.parse(source)
        except SyntaxError: skipped["syntax_error"].append(rel); continue
        analyzed += 1
    skipped = {k: tuple(sorted(v)) for k, v in skipped.items() if v}
    return CoverageReport(len(discovered), analyzed, sum(map(len, skipped.values())), skipped, tuple(families), Fraction(analyzed, len(discovered) or 1))

def _agent_finding(agent: str, item, root: Path) -> Finding:
    path, line, description = item.path, item.line, item.description
    return Finding("OBSERVED", "CODE FACT", path, description,
                   (Evidence("source", f"{path}:{line}", description),),
                   f"AST detector emitted this observation: {item.family}.", agent)

def run_specialized_pipeline(repo: str | Path, output_dir: str | Path, max_connected: int = 100) -> dict[str, Any]:
    root, out = Path(repo).resolve(), Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic(); triage_manifest = archaeologist.assess(root)
    connected = triage_manifest.summary.get("CONNECTED_ALIVE", 0)
    if connected > max_connected: raise ValueError(f"scope guard: {connected} CONNECTED_ALIVE modules exceeds max_connected={max_connected}")
    coverage = _coverage(root)
    bug = bug_investigator.investigate(triage_manifest)
    security_result = security_auditor.audit(root); integrity_result = integrity_inspector.inspect(root)
    security, integrity = security_result.findings, integrity_result.findings
    findings = list(bug.verification.findings)
    findings = [Finding(f.category, f.epistemic_level, f.module_path, f.description, f.evidence, f.reasoning, "bug_investigator") for f in findings]
    findings += [_agent_finding("security_auditor", x, root) for x in security]
    findings += [_agent_finding("integrity_inspector", x, root) for x in integrity]
    verification = VerificationManifest("2.0", "0.1.0", bug.verification.hypotheses_schema_version, str(root), int(time.time()), tuple(findings), bug.verification.discarded, bug.verification.ast_verified_families, bug.verification.ast_unverified_families)
    coverage = CoverageReport(coverage.files_discovered, coverage.files_analyzed, coverage.files_skipped, coverage.skipped_reasons, verification.ast_verified_families, coverage.coverage_ratio)
    triage_path, hypotheses_path = out / "triage-manifest.json", out / "hypotheses-manifest.json"
    verification_path, sealed_path, coverage_path = out / "verification-manifest.json", out / "verification-manifest.sealed.json", out / "coverage-report.json"
    report_path = out / "forge-report.html"
    write_manifest(triage_manifest, triage_path); write_hypotheses_manifest(bug.manifest, hypotheses_path)
    write_verification_manifest(verification, verification_path); write_sealed_manifest(verification, sealed_path); coverage_path.write_text(json.dumps(coverage.to_dict(), indent=2, sort_keys=True) + "\n")
    metrics = {"archaeologist": {"modules_classified": len(triage_manifest.modules), "elapsed_seconds": round(time.monotonic()-started, 6)}, "bug_investigator": {"hypotheses_generated": len(bug.hypotheses), "discarded": len(verification.discarded), "survived": len([f for f in findings if f.agent == "bug_investigator"])}, "security_auditor": {"findings_per_family": {family: sum(x.family == family for x in security) for family in ("hardcoded-credential", "unsafe-deserialization", "path-traversal")}}, "integrity_inspector": {"findings_per_family": {family: sum(x.family == family for x in integrity) for family in ("decision-adjacent-float", "unversioned-serialization")}}}
    metrics["bug_investigator"]["examinations"] = {m.path: ("examined_with_findings" if any(f.module_path == m.path for f in findings if f.agent == "bug_investigator") else "examined_clean") if m.module_class.value == "CONNECTED_ALIVE" else "excluded_by_scope" for m in triage_manifest.modules}
    metrics["security_auditor"]["examinations"] = security_result.examinations
    metrics["integrity_inspector"]["examinations"] = integrity_result.examinations
    report_composer.compose(triage_path, hypotheses_path, sealed_path, report_path, coverage_path, metrics)
    return {"repo": str(root), "connected_alive": connected, "findings": len(findings), "coverage": coverage.to_dict(), "artifacts": {"triage": str(triage_path), "hypotheses": str(hypotheses_path), "verification": str(verification_path), "sealed": str(sealed_path), "coverage": str(coverage_path), "report": str(report_path)}}


def run_pipeline(repo: str | Path, output_dir: str | Path, max_connected: int = 100) -> dict[str, Any]:
    """Run specialized agents sequentially and refuse broad downstream scope.

    The guard runs immediately after ``triage()`` returns. It prevents the
    remaining agents from running, but cannot make triage itself cheaper.
    """
    root = Path(repo).resolve()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    triage_manifest = triage(root)
    connected = triage_manifest.summary.get(
        "CONNECTED_ALIVE",
        sum(m.module_class.value == "CONNECTED_ALIVE" for m in triage_manifest.modules),
    )
    if connected > max_connected:
        raise ValueError(f"scope guard: {connected} CONNECTED_ALIVE modules exceeds max_connected={max_connected}")
    triage_path = out / "triage-manifest.json"
    hypotheses_path = out / "hypotheses-manifest.json"
    verification_path = out / "verification-manifest.json"
    sealed_path = out / "verification-manifest.sealed.json"
    report_path = out / "forge-report.html"
    write_manifest(triage_manifest, triage_path)
    hypotheses = generate_hypotheses(triage_manifest)
    write_hypotheses_manifest(hypotheses, hypotheses_path)
    verification = verify_hypotheses(hypotheses)
    write_verification_manifest(verification, verification_path)
    write_sealed_manifest(verification, sealed_path)
    render_report(triage_path, hypotheses_path, sealed_path, report_path)
    return {
        "repo": str(root),
        "output_dir": str(out.resolve()),
        "connected_alive": connected,
        "findings": len(verification.findings),
        "discarded": len(verification.discarded),
        "artifacts": {name: str(path) for name, path in {
            "triage": triage_path, "hypotheses": hypotheses_path,
            "verification": verification_path, "sealed": sealed_path,
            "report": report_path,
        }.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded FORGE agents in sequence")
    parser.add_argument("repo", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-run"))
    parser.add_argument("--max-connected", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(run_pipeline(args.repo, args.output_dir, args.max_connected), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
