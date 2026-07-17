"""Seeded recall measurement for the FORGE detector scope.

Recall is deliberately measured only for families the corresponding FORGE
agent models.  Benign twins are precision guardrails, and out-of-scope
fixtures are reported separately so a clean result is never misread as a
whole-repository claim.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from forge.agents.security_auditor import audit as audit_security
from forge.precision import FindingIdentity, _findings
from forge.severity import severity_for


_KINDS = frozenset({"positive", "benign_twin", "out_of_scope"})
_DETECTION_MODES = frozenset({"static", "induction", "both"})
_TIERS = frozenset({"canonical", "variant"})
_EXPECTED_TODAY = frozenset({"HIT", "MISS", "UNKNOWN"})
_VARIANT_DISPOSITIONS = frozenset({"close_gap", "scope_boundary", "undecided"})
_OUT_OF_SCOPE_STATEMENT = (
    "Excluded from the recall denominator: no finding is not a claim that the repository has no bugs."
)


def _identity(case: dict[str, Any]) -> FindingIdentity:
    if case.get("kind") != "positive":
        raise ValueError(f"only positive recall cases have an expected identity: {case.get('name')!r}")
    missing = {"family", "path", "expected_line"} - set(case)
    if missing:
        raise ValueError(f"recall positive {case.get('name')!r} missing {sorted(missing)}")
    # ``path`` selects the fixture directory. Detector paths are relative to
    # that directory (usually ``main.py``), so ``expected_path`` preserves the
    # detector's coordinate system for the measured triple.
    return (str(case["family"]), str(case.get("expected_path", "main.py")), int(case["expected_line"]))


def _validate_case(case: dict[str, Any]) -> None:
    missing = {"name", "agent", "path", "kind", "detection_mode", "notes"} - set(case)
    if missing:
        raise ValueError(f"recall case missing {sorted(missing)}: {case!r}")
    if case["kind"] not in _KINDS:
        raise ValueError(f"invalid recall kind {case['kind']!r} in {case['name']!r}")
    if case["detection_mode"] not in _DETECTION_MODES:
        raise ValueError(f"invalid detection_mode {case['detection_mode']!r} in {case['name']!r}")
    if case["kind"] == "positive":
        _identity(case)
        tier = case.get("tier", "canonical")
        if tier not in _TIERS:
            raise ValueError(f"invalid recall tier {tier!r} in {case['name']!r}")
        if tier == "variant":
            if case.get("expected_today") not in _EXPECTED_TODAY:
                raise ValueError(f"variant needs expected_today in {case['name']!r}")
            if case.get("disposition") not in _VARIANT_DISPOSITIONS:
                raise ValueError(f"variant needs disposition in {case['name']!r}")
    elif "family" not in case:
        raise ValueError(f"{case['kind']} recall case needs a family for an observable result: {case['name']!r}")


def _run_case(root: Path, case: dict[str, Any]) -> tuple[set[FindingIdentity], bool]:
    """Run one case and say whether it used isolated induction."""
    induce = case["detection_mode"] in {"induction", "both"}
    return _findings(case["agent"], root / case["path"], induce=induce), induce


def _security_metadata(case_root: Path) -> dict[FindingIdentity, dict[str, str]]:
    """Return the secondary axes for static security positives.

    The exact identity remains the recall truth.  These fields make a claimed
    controlability/severity regression visible without redefining recall.
    """
    metadata: dict[FindingIdentity, dict[str, str]] = {}
    for finding in audit_security(case_root).findings:
        identity = (finding.family, finding.path, finding.line)
        metadata[identity] = {
            "controllability": finding.controllability,
            "severity": severity_for(
                finding.path,
                "CODE FACT",
                finding.description,
                "security_auditor",
                family=finding.family,
                controllability=finding.controllability,
                exploitability=finding.exploitability,
            ),
        }
    return metadata


def _score(detections: list[bool]) -> dict[str, Any]:
    detected = sum(detections)
    total = len(detections)
    return {"detected": detected, "total": total, "recall": round(detected / total, 6) if total else 1.0}


def _scores_by_family(detections: dict[str, list[bool]]) -> dict[str, dict[str, Any]]:
    return {family: _score(values) for family, values in sorted(detections.items())}


def _variant_baseline(root: Path) -> dict[str, Any] | None:
    path = root / "recall-variants-baseline.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("recall_variants_schema_version") != "1.0":
        raise ValueError(f"unsupported recall variants baseline at {path}")
    return data


def run_recall(corpus: str | Path) -> dict[str, Any]:
    """Measure seeded recall without conflating it with precision or scope."""
    root = Path(corpus).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest.get("recall_cases")
    if not isinstance(cases, list):
        raise ValueError("recall corpus must declare a recall_cases list")

    canonical: dict[str, list[bool]] = defaultdict(list)
    variants: dict[str, list[bool]] = defaultdict(list)
    twin_failures: list[str] = []
    case_rows: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    for case in cases:
        _validate_case(case)
        case_root = root / case["path"]
        actual, induced = _run_case(root, case)
        family_actual = sorted(identity for identity in actual if identity[0] == case["family"])
        row: dict[str, Any] = {
            "case": case["name"],
            "kind": case["kind"],
            "agent": case["agent"],
            "family": case["family"],
            "detection_mode": case["detection_mode"],
            "induction_enabled": induced,
            "actual_family_findings": [
                {"family": family, "path": path, "line": line} for family, path, line in family_actual
            ],
            "notes": case["notes"],
        }
        if case["kind"] == "positive":
            expected = _identity(case)
            metadata = _security_metadata(case_root) if case["agent"] == "security_auditor" else {}
            observed = metadata.get(expected, {})
            secondary_checks = {
                "controllability": case.get("controllability"),
                "expected_severity_min": case.get("expected_severity_min"),
            }
            control_ok = (
                secondary_checks["controllability"] is None
                or observed.get("controllability") == secondary_checks["controllability"]
            )
            severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            severity_ok = (
                secondary_checks["expected_severity_min"] is None
                or severity_order.get(observed.get("severity", "INFO"), 0)
                >= severity_order[secondary_checks["expected_severity_min"]]
            )
            detected = expected in actual and control_ok and severity_ok
            tier = case.get("tier", "canonical")
            (variants if tier == "variant" else canonical)[expected[0]].append(detected)
            row["expected_finding"] = {"family": expected[0], "path": expected[1], "line": expected[2]}
            row["detected"] = detected
            row["tier"] = tier
            if observed:
                row["observed_secondary_axes"] = observed
            if any(value is not None for value in secondary_checks.values()):
                row["secondary_checks"] = secondary_checks | {"passed": control_ok and severity_ok}
            if tier == "variant":
                observed_today = "HIT" if detected else "MISS"
                row["expected_today"] = case["expected_today"]
                row["observed_today"] = observed_today
                row["hypothesis_confirmed"] = None if case["expected_today"] == "UNKNOWN" else case["expected_today"] == observed_today
                row["disposition"] = case["disposition"]
        elif case["kind"] == "benign_twin":
            clean = not family_actual
            row["clean"] = clean
            row["regression_of"] = case.get("regression_of")
            if not clean:
                twin_failures.append(case["name"])
        else:
            row["observed_findings"] = [
                {"family": family, "path": path, "line": line} for family, path, line in sorted(actual)
            ]
            row["coverage_statement"] = _OUT_OF_SCOPE_STATEMENT
            out_of_scope.append(row)
        case_rows.append(row)

    canonical_by_family = _scores_by_family(canonical)
    variant_by_family = _scores_by_family(variants)
    canonical_global = _score([detected for values in canonical.values() for detected in values])
    variant_global = _score([detected for values in variants.values() for detected in values])
    floor = manifest.get("recall_floor", {})
    minimum = float(floor.get("per_family", 0.0))
    twin_limit = int(floor.get("fp_on_twins", 0))
    below_floor = {family: score["recall"] for family, score in canonical_by_family.items() if score["recall"] < minimum}
    known_gaps = [
        {"case": row["case"], "family": row["family"], "disposition": row["disposition"]}
        for row in case_rows
        if row.get("tier") == "variant" and not row["detected"] and row["disposition"] != "scope_boundary"
    ]
    hypothesis_mismatches = [
        {"case": row["case"], "expected_today": row["expected_today"], "observed_today": row["observed_today"]}
        for row in case_rows
        if row.get("tier") == "variant" and row["hypothesis_confirmed"] is False
    ]
    baseline = _variant_baseline(root)
    baseline_by_family = (baseline or {}).get("recall_variant_by_family", {})
    variant_regressions = {
        family: {"baseline": score["recall"], "observed": variant_by_family.get(family, {"recall": 0.0})["recall"]}
        for family, score in baseline_by_family.items()
        if variant_by_family.get(family, {"recall": 0.0})["recall"] < score["recall"]
    }
    baseline_gaps = (baseline or {}).get("known_gaps")
    unrecorded_gaps = known_gaps if baseline_gaps is None else [gap for gap in known_gaps if gap not in baseline_gaps]
    stale_baseline_gaps = [] if baseline_gaps is None else [gap for gap in baseline_gaps if gap not in known_gaps]
    return {
        "recall_schema_version": "2.0",
        "corpus": str(root),
        "cases": case_rows,
        "recall_canonical_by_family": canonical_by_family,
        "recall_canonical_global": canonical_global,
        "recall_variant_by_family": variant_by_family,
        "recall_variant_global": variant_global,
        "recall_by_family": canonical_by_family,
        "recall_global": canonical_global,
        "fp_on_twins": {"count": len(twin_failures), "cases": twin_failures},
        "out_of_scope": out_of_scope,
        "known_gaps": known_gaps,
        "hypothesis_mismatches": hypothesis_mismatches,
        "variant_baseline": baseline,
        "gates": {
            "minimum_recall_per_family": minimum,
            "maximum_fp_on_twins": twin_limit,
            "below_canonical_recall_floor": below_floor,
            "variant_regressions": variant_regressions,
            "unrecorded_known_gaps": unrecorded_gaps,
            "stale_baseline_gaps": stale_baseline_gaps,
            "passed": not below_floor and len(twin_failures) <= twin_limit and not variant_regressions and not unrecorded_gaps,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="tests/corpus")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = run_recall(args.corpus)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if not result["gates"]["passed"]:
        raise SystemExit(
            "seeded recall gate failed: "
            f"canonical_below={result['gates']['below_canonical_recall_floor']}, "
            f"twins={result['fp_on_twins']['cases']}, "
            f"variant_regressions={result['gates']['variant_regressions']}, "
            f"unrecorded_gaps={result['gates']['unrecorded_known_gaps']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
