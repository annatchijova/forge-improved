import json

from forge.precision import run_precision


def test_golden_corpus_has_three_positive_and_negative_cases_per_agent():
    result = run_precision("tests/corpus")
    # Base rate is 3 positive + 3 negative per agent. Deviations, each
    # covering one detector rule with no equivalent in the other agents:
    # - integrity_inspector +1/+2:
    #   - negative-4: a machine_learning-domain module whose float() would
    #     otherwise trigger decision-adjacent-float (domain-aware
    #     suppression).
    #   - positive-4 / negative-5: money-as-float (SQLite REAL money column
    #     and round()-over-division on a money-shaped name, with a
    #     Fraction-based negative counterpart) - a value can be float-typed
    #     without ever calling float(), a separate detection path entirely.
    # - security_auditor +2/+2:
    #   - positive-4 / negative-4: os.getenv(name, default) where default is
    #     a hardcoded credential - the assignment's value is a Call, not a
    #     Constant, so the base hardcoded-credential check (which only
    #     matches bare literal assignments) never sees it.
    #   - positive-5 / negative-5: unverified-webhook - a route named like a
    #     webhook (an external system's callback) that mutates state with no
    #     FastAPI Depends(...) and no signature/HMAC check in its body.
    #     Scoped to "webhook"-named routes specifically, since a blanket
    #     "no Depends()" rule would flag this project's own intentionally
    #     public checkout/cart endpoints.
    expected_positives = {"integrity_inspector": 4, "security_auditor": 5, "web_auditor": 3}
    expected_negatives = {"integrity_inspector": 5, "security_auditor": 5, "web_auditor": 3}
    assert result["case_count"] == sum(expected_positives.values()) + sum(expected_negatives.values())
    for agent in {row["agent"] for row in result["cases"]}:
        cases = [row for row in result["cases"] if row["agent"] == agent]
        assert len([row for row in cases if row["expected_families"]]) == expected_positives[agent]
        assert len([row for row in cases if not row["expected_families"]]) == expected_negatives[agent]


def test_golden_corpus_baseline_is_exact():
    result = run_precision("tests/corpus")
    assert all(score["f1"] == 1.0 for score in result["by_family"].values()), json.dumps(result, indent=2)
