import json

from forge.precision import run_precision


def test_golden_corpus_has_three_positive_and_negative_cases_per_agent():
    result = run_precision("tests/corpus")
    # integrity_inspector carries one extra negative case (negative-4): a
    # machine_learning-domain module whose float() would otherwise trigger
    # decision-adjacent-float, covering the domain-aware suppression that
    # security_auditor/web_auditor don't have an equivalent rule for.
    assert result["case_count"] == 19
    for agent in {row["agent"] for row in result["cases"]}:
        cases = [row for row in result["cases"] if row["agent"] == agent]
        expected_negatives = 4 if agent == "integrity_inspector" else 3
        assert len([row for row in cases if row["expected_families"]]) == 3
        assert len([row for row in cases if not row["expected_families"]]) == expected_negatives


def test_golden_corpus_baseline_is_exact():
    result = run_precision("tests/corpus")
    assert all(score["f1"] == 1.0 for score in result["by_family"].values()), json.dumps(result, indent=2)
