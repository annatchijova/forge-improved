"""Objective, serializable metrics derived from one audit run.

This module intentionally contains accounting, not detection. Every value is
either counted from an existing artifact or marked unavailable when FORGE does
not collect the required evidence.
"""
from __future__ import annotations

import ast
import hashlib
import platform
import sys
from dataclasses import asdict
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from forge.models import ModuleClass
from forge.canonical import canonical_json
from forge.severity import finding_family
from forge.disposition import determine_disposition


def _ratio(covered: int, total: int) -> dict[str, int]:
    return {"covered": covered, "total": total}


def _loc(path: Path) -> tuple[int, int, int]:
    """Return total, code, comment lines without treating prose as code."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return 0, 0, 0
    total = len(lines)
    blank = sum(not line.strip() for line in lines)
    comments = sum(line.lstrip().startswith(("#", "//", "/*", "*", "--")) for line in lines)
    return total, total - blank - comments, comments


def _python_structure(path: Path) -> tuple[int, int, int]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return 0, 0, 0
    functions = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
    classes = sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
    methods = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            methods += sum(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) for child in node.body)
    return functions, classes, methods


def _files_by_language(paths: Iterable[Path]) -> dict[str, int]:
    extensions = {
        ".py": "Python", ".java": "Java", ".rs": "Rust", ".c": "C/C++", ".cc": "C/C++",
        ".cpp": "C/C++", ".h": "C/C++", ".js": "JavaScript/TypeScript", ".jsx": "JavaScript/TypeScript",
        ".ts": "JavaScript/TypeScript", ".tsx": "JavaScript/TypeScript",
    }
    counts = Counter(extensions.get(path.suffix.lower(), "Other") for path in paths)
    return {key: counts[key] for key in sorted(counts)}


def collect_metrics(*, root: Path, discovered: list[Path], triage: Any, coverage: Any,
                    governance: Any, findings: Iterable[Any], discarded: Iterable[dict[str, Any]],
                    trace: Any, skills: Iterable[dict[str, Any]],
                    hypothesis_limitations: Iterable[str] = ()) -> dict[str, Any]:
    """Build all currently supported metric layers from already collected data."""
    files = list(discovered)
    totals = [_loc(path) for path in files]
    python_entries = [(path, _python_structure(path)) for path in files if path.suffix.lower() == ".py"]
    structures = [structure for _, structure in python_entries]
    findings = list(findings)
    bug_findings = [finding for finding in findings if finding.agent == "bug_investigator"]
    discarded = list(discarded)
    skills = list(skills)
    classes = Counter(item.module_class.value for item in triage.modules)
    domains = Counter(domain for hypothesis in governance.hypotheses for domain in hypothesis.domains)
    evidence = Counter(item.kind for finding in findings for item in finding.evidence)
    outcomes = Counter(item.outcome for item in findings)
    applicability = Counter(state for states in governance.applicability.values() for state in states.values())
    event_kinds = Counter(event.kind for event in trace.events)
    skipped = sum(coverage.skipped_reasons.values(), ())
    analyzed_modules = sum(item.module_class.value == ModuleClass.CONNECTED_ALIVE.value for item in triage.modules)

    total_loc = sum(item[0] for item in totals)
    comment_loc = sum(item[2] for item in totals)
    blank_loc = sum(total - code - comments for total, code, comments in totals)
    config_names = {"pyproject.toml", "setup.py", "requirements.txt", "package.json", "Cargo.toml", "go.mod", "pom.xml", "Makefile", "Dockerfile"}
    documentation = {".md", ".rst", ".txt"}
    tests = sum("test" in path.name.lower() or "tests" in path.parts for path in files)

    repo = {
        "files_discovered": len(files),
        "directories": len({path.parent.relative_to(root) for path in files}),
        "modules": len(triage.modules),
        "files_by_language": _files_by_language(files),
        "loc": {"total": total_loc, "code": total_loc - comment_loc - blank_loc, "comment": comment_loc, "blank": blank_loc},
        "functions": sum(item[0] for item in structures),
        "classes": sum(item[1] for item in structures),
        "methods": sum(item[2] for item in structures),
        "configuration_files": sum(path.name in config_names for path in files),
        "tests": tests,
        "documentation_files": sum(path.suffix.lower() in documentation for path in files),
        "git_commits_analyzed": None,
        "branches_inspected": None,
        "tags_inspected": None,
    }
    scope = {
        "files_analyzed": coverage.files_analyzed,
        "files_skipped": coverage.files_skipped,
        "modules_excluded": len(triage.modules) - analyzed_modules,
        "out_of_scope_modules": [item.path for item in triage.modules if item.module_class.value != ModuleClass.CONNECTED_ALIVE.value],
        "coverage": coverage.to_dict()["coverage_ratio"],
        "lines_analyzed": sum(totals[index][0] for index, path in enumerate(files) if path.suffix.lower() == ".py" and str(path.relative_to(root)) not in skipped),
        "functions_analyzed": sum(structure[0] for path, structure in python_entries if str(path.relative_to(root)) not in skipped),
        "asts_built": coverage.files_analyzed,
        "repositories_chained": 1,
    }
    discovery = {name: classes.get(name, 0) for name in ("CONNECTED_ALIVE", "FOSSIL_HIGH_RISK", "FOSSIL_LOW_RISK", "DEAD_WEIGHT", "DUPLICATE", "UNKNOWN")}
    discovery.update({"mixed_domain_modules": sum(len(item.domains) > 1 for item in governance.hypotheses), "average_dependency_degree": None, "dependency_graph_size": None})
    skill_counts = {"skills_loaded": len(skills), "skills_activated": applicability["APPLICABLE"], "skills_not_applicable": applicability["NOT_APPLICABLE"], "undetermined_skills": applicability["UNDETERMINED"], "contracts_executed": applicability["APPLICABLE"], "contracts_skipped": applicability["NOT_APPLICABLE"], "contract_failures": applicability["ERROR"], "evidence_obligations_satisfied": None, "evidence_obligations_missing": None, "limitations_emitted": len(governance.limitations)}
    agent = {
        "abduction": {"patterns_observed": len(discarded) + len(bug_findings), "hypotheses_generated": event_kinds.get("hypotheses_generated", 0), "hypotheses_merged": None, "hypotheses_discarded": len(discarded), "average_evidence_per_hypothesis": None},
        "verification": {"checks_executed": len(bug_findings) + len(discarded), "checks_passed": len(discarded), "checks_failed": 0, "checks_unresolved": len(bug_findings), "benign_explanations_accepted": len(discarded), "benign_explanations_rejected": 0, "structural_proofs_found": len(discarded), "checks_note": "Surviving hypotheses are unresolved candidates, not failed tests; dynamic induction is required before calling them defects."},
        "integrity_inspector": {"contracts_evaluated": applicability["APPLICABLE"], "applicable": applicability["APPLICABLE"], "not_applicable": applicability["NOT_APPLICABLE"], "undetermined": applicability["UNDETERMINED"], "protocol_gaps": outcomes["PROTOCOL_GAP"], "design_inconsistencies": outcomes["DESIGN_INCONSISTENCY"]},
    }
    evidence_metrics = {"evidence_items": sum(evidence.values()), "primary_evidence": evidence.get("source", 0), "secondary_evidence": sum(value for key, value in evidence.items() if key != "source"), "by_kind": dict(sorted(evidence.items())), "evidence_reused": None, "evidence_conflicts": None}
    finding_metrics = {"by_outcome": {key: outcomes.get(key, 0) for key in ("OBSERVED", "PROTOCOL_GAP", "DESIGN_INCONSISTENCY", "UNDETERMINED", "NOT_APPLICABLE")}, "discarded_hypotheses": len(discarded), "by_agent": dict(Counter(item.agent for item in findings)), "by_module": dict(Counter(item.module_path for item in findings))}
    finding_metrics["by_severity"] = dict(Counter(getattr(item, "severity", "MEDIUM") for item in findings))
    finding_metrics["by_family"] = dict(Counter(finding_family(item.description) for item in findings))
    finding_metrics["by_epistemic_level"] = dict(Counter(item.epistemic_level for item in findings))
    finding_metrics["induction"] = {
        "confirmed": sum(item.epistemic_level == "CONFIRMED BY INDUCTION" for item in findings),
        "undetermined": sum("induction was undetermined" in item.reasoning.lower() for item in findings),
        "falsified": sum("induction falsified" in item.get("reason", "").lower() for item in discarded),
    }
    finding_digest = hashlib.sha256(canonical_json([asdict(item) for item in findings]).encode("utf-8")).hexdigest()
    trace_metrics = {"runtime_events": len(trace.events), "events_hashed": len(trace.events), "events_verified": None, "artifacts_produced": None, "hash_chain_length": None, "chain_verification": None, "tampering_detected": None, "partial_trace": event_kinds.get("run_failed", 0) > 0}
    reproducibility = {"runtime_deterministic": None, "seed_used": None, "environment": {"python": sys.version.split()[0], "os": platform.platform()}, "forge_version": "0.1.0", "skill_versions": {item["name"]: item["version"] for item in skills}, "schema_versions": {"triage": triage.schema_version}, "artifact_hashes": None, "seal_verified": None}
    finding_metrics["finding_digest"] = finding_digest
    executable_count = len(skills)
    quality = {"repository_coverage": _ratio(coverage.files_analyzed, coverage.files_discovered), "module_coverage": _ratio(analyzed_modules, len(triage.modules)), "contract_coverage": _ratio(applicability["APPLICABLE"], sum(applicability.values()) or 1), "contract_coverage_note": f"{executable_count} executable skill(s) loaded; this ratio measures applicability observations for executable skills only, not the documented skills catalog.", "evidence_completeness": None, "evidence_completeness_note": "Requires an explicit obligation ledger mapping each executed contract obligation to satisfied or missing Evidence items.", "verification_coverage": None, "verification_coverage_note": "Requires a count of planned checks versus checks actually executed, including skipped checks and their reasons."}
    disposition = determine_disposition(coverage=coverage, triage=triage, governance=governance, findings=findings)
    limitations = list(governance.limitations) + list(hypothesis_limitations)
    if coverage.files_skipped:
        limitations.append(f"{coverage.files_skipped} discovered file(s) were skipped; see skipped_reasons for the exact paths and policy categories.")
    if scope["modules_excluded"]:
        limitations.append(f"{scope['modules_excluded']} triaged module(s) were outside CONNECTED_ALIVE audit scope.")
    if applicability["UNDETERMINED"]:
        limitations.append(f"{applicability['UNDETERMINED']} skill applicability result(s) were UNDETERMINED; no conclusion was inferred for them.")
    if bug_findings:
        limitations.append(f"{len(bug_findings)} hypothesis/hypotheses survived structural verification without dynamic induction; they remain plausible hypotheses, not confirmed defects.")
    # Preserve ordering while avoiding repeated limitation text from multiple layers.
    limitations = list(dict.fromkeys(limitations))
    return {"metrics_schema_version": "1.0", "repository": repo, "scope": scope, "discovery": discovery, "domain_classification": {"modules_by_domain": dict(sorted(domains.items())), "hypothesis_confidence": [{"module_path": item.module_path, "domains": item.domains, "confidence": {"numerator": item.confidence.numerator, "denominator": item.confidence.denominator}, "alternatives": item.alternatives, "evidence_count": len(item.evidence)} for item in governance.hypotheses]}, "skill_runtime": skill_counts, "agents": agent, "evidence": evidence_metrics, "findings": finding_metrics, "audit_disposition": disposition.to_dict(), "audit_trail": trace_metrics, "reproducibility": reproducibility, "honest_degradation": {"skipped_reasons": coverage.skipped_reasons, "limitations": limitations}, "quality": quality}
