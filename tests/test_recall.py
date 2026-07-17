import json

from forge.recall import run_recall


def test_seeded_recall_manifest_declares_the_three_epistemic_case_kinds():
    manifest = json.loads(open("tests/corpus/manifest.json", encoding="utf-8").read())
    assert manifest["recall_schema_version"] == "2.0"
    assert {case["kind"] for case in manifest["recall_cases"]} == {
        "positive", "benign_twin", "out_of_scope",
    }
    positives = [case for case in manifest["recall_cases"] if case["kind"] == "positive"]
    assert all({"family", "expected_line"} <= set(case) for case in positives)


def test_seeded_recall_corpus_meets_its_declared_gate_and_keeps_scope_separate():
    result = run_recall("tests/corpus")
    assert result["gates"]["passed"]
    assert all(score["recall"] >= 0.90 for score in result["recall_canonical_by_family"].values())
    assert result["fp_on_twins"] == {"count": 0, "cases": []}
    assert result["out_of_scope"]
    assert all("Excluded from the recall denominator" in row["coverage_statement"] for row in result["out_of_scope"])
    assert result["recall_canonical_global"]["total"] == sum(score["total"] for score in result["recall_canonical_by_family"].values())


def test_seeded_recall_baseline_is_versioned_with_the_corpus():
    baseline = json.loads(open("tests/corpus/recall-baseline.json", encoding="utf-8").read())
    result = run_recall("tests/corpus")
    assert baseline["recall_schema_version"] == result["recall_schema_version"]
    assert baseline["recall_by_family"] == result["recall_by_family"]
    assert baseline["recall_global"] == result["recall_global"]
    assert baseline["fp_on_twins"] == result["fp_on_twins"]
    assert baseline["out_of_scope_case_count"] == len(result["out_of_scope"])


def test_variant_recall_is_versioned_without_turning_known_misses_into_build_failures():
    baseline = json.loads(open("tests/corpus/recall-variants-baseline.json", encoding="utf-8").read())
    result = run_recall("tests/corpus")
    variants = [case for case in result["cases"] if case.get("tier") == "variant"]
    assert variants
    assert all(case["expected_today"] in {"HIT", "MISS", "UNKNOWN"} for case in variants)
    assert all(case["disposition"] in {"close_gap", "scope_boundary", "undecided"} for case in variants)
    assert result["recall_variant_by_family"] == baseline["recall_variant_by_family"]
    assert result["recall_variant_global"] == baseline["recall_variant_global"]
    assert result["known_gaps"] == baseline["known_gaps"]
    assert result["gates"]["variant_regressions"] == {}
    assert result["gates"]["unrecorded_known_gaps"] == []
    assert result["known_gaps"]
