import json

import pytest

import forge.precision as precision
from forge.precision import _scores, run_precision


def test_golden_corpus_declares_exact_findings_and_all_four_agents():
    manifest = json.loads(open("tests/corpus/manifest.json", encoding="utf-8").read())
    assert manifest["precision_schema_version"] == "2.0"
    assert {case["agent"] for case in manifest["cases"]} == {
        "integrity_inspector", "security_auditor", "web_auditor", "bug_investigator",
    }
    assert all("expected_findings" in case for case in manifest["cases"])
    for case in manifest["cases"]:
        for finding in case["expected_findings"]:
            assert set(finding) == {"family", "path", "line"}


def test_exact_score_counts_wrong_line_as_one_fp_and_one_fn():
    scores = _scores([{
        "case": "wrong-location",
        "expected": {("path-traversal", "main.py", 10)},
        "actual": {("path-traversal", "main.py", 11)},
    }])
    assert scores["path-traversal"] == {
        "true_positive": 0,
        "false_positive": 1,
        "false_negative": 1,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
    }


def test_golden_corpus_has_ledger_regressions_and_initial_global_floor():
    result = run_precision("tests/corpus")
    ledger_cases = {row["case"]: row for row in result["cases"] if row["case"].startswith("fp-")}
    assert set(ledger_cases) == {
        "fp-001-negative-telemetry", "fp-001-positive-return", "fp-002-versioned-payload",
        "fp-003-presentation-json", "fp-004-named-error-contract",
    }
    assert ledger_cases["fp-001-positive-return"]["actual_findings"]
    assert all(not row["actual_findings"] for name, row in ledger_cases.items() if name != "fp-001-positive-return")
    assert result["global"]["precision"] >= 0.95
    assert result["global"]["recall"] >= 0.90


def test_family_view_is_retained_as_an_aggregate_over_exact_findings():
    result = run_precision("tests/corpus")
    assert result["by_family"]["money-as-float"]["true_positive"] == 2
    assert result["by_finding_family"]["money-as-float"]["true_positive"] == 5


def test_precision_cli_enforces_global_precision_and_recall_gates(monkeypatch):
    monkeypatch.setattr(precision, "run_precision", lambda _: {
        "by_finding_family": {},
        "global": {"precision": 0.94, "recall": 0.89},
    })
    with pytest.raises(SystemExit, match="precision below threshold"):
        precision.main(["--min-precision", "0.95"])
    with pytest.raises(SystemExit, match="recall below threshold"):
        precision.main(["--min-recall", "0.90"])
