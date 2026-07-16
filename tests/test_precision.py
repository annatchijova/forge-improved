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
    # - integrity_inspector negative-6: seal_findings() (seal_manifest()'s
    #   own sibling) and a brand-new "widget_schema_version" key, both found
    #   via a self-audit of forge/sealing.py that FORGE's own versioning
    #   allowlist did not recognize.
    # - integrity_inspector negative-7: a json.dumps() call inside the body
    #   of a trusted function itself (canonical_json), not a caller of it -
    #   found via a self-audit of forge/canonical.py. _enclosing_function()
    #   existed in this file already but was never wired into the check.
    # - integrity_inspector negative-8: a "canonical_*"-prefixed function
    #   other than canonical_json (found: canonical_findings_bytes in
    #   forge/tiered_report.py), and html.escape(json.dumps(...)) - the
    #   report renderers' presentation shape, previously only recognized
    #   via the f-string (JoinedStr) shape.
    # - integrity_inspector negative-9: a local name assigned from a call to
    #   a versioned-producer function defined in another file
    #   (metrics = collect_metrics(...)), and the transitive case
    #   (load_and_validate() returning validate_independent_results(...)'s
    #   already-versioned dict) - found via self-audits of forge/runtime.py
    #   and forge/agent_independence.py.
    # - integrity_inspector negative-10: json.dumps(...) as a direct
    #   .execute()/.executemany() parameter-tuple element - one column of
    #   an already-versioned SQL row, found via a self-audit of
    #   forge/cronos/store.py. Deliberately narrow (only a tuple passed
    #   directly to execute/executemany, not any enclosing tuple): a
    #   broader version of this check silently suppressed 31 real findings
    #   elsewhere in the codebase.
    # - integrity_inspector negative-11: a json.dumps() call assigned to a
    #   name that is only ever later hashed (hashlib.sha256(...)), never
    #   persisted - found via a self-audit of
    #   forge/agent_independence.py::_fingerprint().
    expected_positives = {"integrity_inspector": 4, "security_auditor": 5, "web_auditor": 3}
    expected_negatives = {"integrity_inspector": 11, "security_auditor": 5, "web_auditor": 3}
    assert result["case_count"] == sum(expected_positives.values()) + sum(expected_negatives.values())
    for agent in {row["agent"] for row in result["cases"]}:
        cases = [row for row in result["cases"] if row["agent"] == agent]
        assert len([row for row in cases if row["expected_families"]]) == expected_positives[agent]
        assert len([row for row in cases if not row["expected_families"]]) == expected_negatives[agent]


def test_golden_corpus_baseline_is_exact():
    result = run_precision("tests/corpus")
    assert all(score["f1"] == 1.0 for score in result["by_family"].values()), json.dumps(result, indent=2)
