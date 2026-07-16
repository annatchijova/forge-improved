"""Golden-corpus precision and recall measurement for deterministic agents."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from forge.agents.integrity_inspector import inspect as inspect_integrity
from forge.agents.security_auditor import audit as audit_security
from forge.agents.web_auditor import audit as audit_web
from forge.detector.stack import triage
from forge.governance.runtime import infer_domains


def _families(agent: str, root: Path) -> set[str]:
    if agent == "integrity_inspector":
        ml_domain_paths = frozenset(
            h.module_path for h in infer_domains(triage(root)) if "machine_learning" in h.domains
        )
        result = inspect_integrity(root, ml_domain_paths=ml_domain_paths)
        return {finding.family for finding in result.findings}
    if agent == "security_auditor":
        result = audit_security(root)
        return {finding.family for finding in result.findings}
    if agent == "web_auditor":
        result, _ = audit_web(root)
        return {finding.family for finding in result.findings}
    raise ValueError(f"unsupported golden-corpus agent: {agent}")


def _scores(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    families = sorted({family for row in rows for family in row["expected"] | row["actual"]})
    scores: dict[str, dict[str, Any]] = {}
    for family in families:
        tp = fp = fn = 0
        for row in rows:
            expected = family in row["expected"]
            actual = family in row["actual"]
            tp += expected and actual
            fp += not expected and actual
            fn += expected and not actual
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        scores[family] = {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }
    return scores


def run_precision(corpus: str | Path) -> dict[str, Any]:
    root = Path(corpus).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        case_root = root / case["path"]
        expected = set(case.get("expected_families", []))
        actual = _families(case["agent"], case_root)
        rows.append({"case": case["name"], "agent": case["agent"], "expected": expected, "actual": actual})
    scores = _scores(rows)
    return {
        "precision_schema_version": "1.0",
        "corpus": str(root),
        "cases": [
            {"case": row["case"], "agent": row["agent"], "expected_families": sorted(row["expected"]), "actual_families": sorted(row["actual"])}
            for row in rows
        ],
        "by_family": scores,
        "case_count": len(rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="tests/corpus")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-f1", type=float, default=0.0)
    args = parser.parse_args(argv)
    result = run_precision(args.corpus)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    below = {family: score["f1"] for family, score in result["by_family"].items() if score["f1"] < args.min_f1}
    if below:
        raise SystemExit(f"golden corpus F1 below threshold {args.min_f1}: {below}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
