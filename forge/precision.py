"""Golden-corpus precision and recall measurement for deterministic agents.

The primary unit of measurement is a finding identity: family, path relative
to its corpus case, and source line.  A family-only score is retained as an
aggregate view, but never used to hide a location error.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from forge.agents.integrity_inspector import inspect as inspect_integrity
from forge.agents.security_auditor import audit as audit_security
from forge.agents.web_auditor import audit as audit_web
from forge.detector.stack import triage
from forge.governance.runtime import infer_domains, run_skills
from forge.hypotheses import generate_hypotheses
from forge.verification import verify_hypotheses

FindingIdentity = tuple[str, str, int]


def _bug_investigator_family(description: str) -> str:
    """Map verified hypothesis descriptions to stable corpus families.

    This deliberately uses the detector's structured description templates,
    not a broad substring guess over arbitrary prose.
    """
    if description.startswith("The parser call `"):
        return "parser-boundary"
    if description.startswith("The subprocess call `") or description.startswith("The dynamic command invocation `"):
        return "subprocess"
    if description.startswith("The decision comparison `") or description.startswith("The tolerance call `"):
        return "decision-adjacent-float"
    if description.startswith("The dynamic evaluation `"):
        return "dynamic-evaluation"
    raise ValueError(f"unmapped bug-investigator hypothesis description: {description!r}")


def _findings(agent: str, root: Path) -> set[FindingIdentity]:
    if agent == "integrity_inspector":
        ml_domain_paths = frozenset(
            h.module_path for h in infer_domains(triage(root)) if "machine_learning" in h.domains
        )
        result = inspect_integrity(root, ml_domain_paths=ml_domain_paths)
        return {(finding.family, finding.path, finding.line) for finding in result.findings}
    if agent == "security_auditor":
        result = audit_security(root)
        return {(finding.family, finding.path, finding.line) for finding in result.findings}
    if agent == "web_auditor":
        result, _ = audit_web(root)
        return {(finding.family, finding.path, finding.line) for finding in result.findings}
    if agent == "bug_investigator":
        verified = verify_hypotheses(generate_hypotheses(triage(root)), induce=True)
        findings: set[FindingIdentity] = set()
        for finding in verified.findings:
            source = next((item.source for item in finding.evidence if item.kind == "source"), "")
            _, separator, line = source.rpartition(":")
            if not separator or not line.isdecimal():
                raise ValueError(f"bug-investigator finding has no source line: {source!r}")
            findings.add((_bug_investigator_family(finding.description), finding.module_path, int(line)))
        return findings
    if agent == "governance_skills":
        result = run_skills(triage(root))
        findings: set[FindingIdentity] = set()
        for finding in result.findings:
            source = next((item.source for item in finding.evidence if item.kind == "source"), "")
            _path, separator, line = source.rpartition(":")
            if not separator or not line.isdecimal():
                raise ValueError(f"governance-skill finding has no source line: {source!r}")
            findings.add((finding.agent, finding.module_path, int(line)))
        return findings
    raise ValueError(f"unsupported golden-corpus agent: {agent}")


def _families(agent: str, root: Path) -> set[str]:
    """Compatibility projection for callers that only need families."""
    return {family for family, _, _ in _findings(agent, root)}


def _score(expected: set[Any], actual: set[Any]) -> dict[str, Any]:
    true_positive = len(expected & actual)
    false_positive = len(actual - expected)
    false_negative = len(expected - actual)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _scores(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Score exact identities, grouped by family.

    A correct family on a wrong line is in both set differences: one false
    positive and one false negative, exactly as an analyst would experience
    it when attempting to locate the reported defect.
    """
    families = sorted({family for row in rows for family, _, _ in row["expected"] | row["actual"]})
    return {
        family: _score(
            {item for row in rows for item in row["expected"] if item[0] == family},
            {item for row in rows for item in row["actual"] if item[0] == family},
        )
        for family in families
    }


def _family_scores(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Keep the original family-presence score as an aggregate view."""
    families = sorted({family for row in rows for family, _, _ in row["expected"] | row["actual"]})
    scores: dict[str, dict[str, Any]] = {}
    for family in families:
        expected = {row["case"] for row in rows if any(item[0] == family for item in row["expected"])}
        actual = {row["case"] for row in rows if any(item[0] == family for item in row["actual"])}
        scores[family] = _score(expected, actual)
    return scores


def _expected_findings(case: dict[str, Any]) -> set[FindingIdentity]:
    raw = case.get("expected_findings")
    if raw is None:
        # Transition compatibility for independently maintained corpora. The
        # repository corpus itself is required to declare exact findings.
        return {(family, "", 0) for family in case.get("expected_families", [])}
    return {(item["family"], item["path"], int(item["line"])) for item in raw}


def run_precision(corpus: str | Path) -> dict[str, Any]:
    root = Path(corpus).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        case_root = root / case["path"]
        expected = _expected_findings(case)
        actual = _findings(case["agent"], case_root)
        rows.append({"case": case["name"], "agent": case["agent"], "expected": expected, "actual": actual})
    by_finding_family = _scores(rows)
    all_expected = {item for row in rows for item in row["expected"]}
    all_actual = {item for row in rows for item in row["actual"]}
    return {
        "precision_schema_version": "2.0",
        "corpus": str(root),
        "cases": [
            {
                "case": row["case"],
                "agent": row["agent"],
                "expected_findings": [
                    {"family": family, "path": path, "line": line} for family, path, line in sorted(row["expected"])
                ],
                "actual_findings": [
                    {"family": family, "path": path, "line": line} for family, path, line in sorted(row["actual"])
                ],
                "expected_families": sorted({family for family, _, _ in row["expected"]}),
                "actual_families": sorted({family for family, _, _ in row["actual"]}),
            }
            for row in rows
        ],
        "by_finding_family": by_finding_family,
        "by_family": _family_scores(rows),
        "global": _score(all_expected, all_actual),
        "case_count": len(rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="tests/corpus")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-f1", type=float, default=0.0)
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    args = parser.parse_args(argv)
    result = run_precision(args.corpus)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    below_f1 = {family: score["f1"] for family, score in result["by_finding_family"].items() if score["f1"] < args.min_f1}
    if below_f1:
        raise SystemExit(f"golden corpus F1 below threshold {args.min_f1}: {below_f1}")
    if result["global"]["precision"] < args.min_precision:
        raise SystemExit(f"golden corpus precision below threshold {args.min_precision}: {result['global']['precision']}")
    if result["global"]["recall"] < args.min_recall:
        raise SystemExit(f"golden corpus recall below threshold {args.min_recall}: {result['global']['recall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
