from forge.harness.mining import mine, mine_ledger, combine, LEDGER_AGENT
from forge.harness.proposal import propose
from forge.harness.validation import validate, run_held_in_gate
def run(reason, path):
    return {"manifest":{"discarded":[{"reason":reason,"module_path":path,"agent":"bug_investigator","family":"float comparison","mechanism":"unstripped inline comment"}],"findings":[]}}
def test_mining_clusters_exact_recurring_signature():
    bundle=mine([run("AST proves explicit tolerance",f"m{i}.py") for i in range(3)])
    assert len(bundle.clusters)==1 and bundle.clusters[0].frequency==3
def test_proposal_targets_real_comment_fix():
    p=propose(mine([run("false positive from unstripped inline comment","x.py")]))[0]
    assert p.target_file=="forge/hypotheses.py" and p.target_function=="_candidates" and "_code_before_comment" in p.change
def test_validation_exact_acceptance_rule():
    assert validate("p",1,2,5,5).accepted
    assert not validate("p",1,2,5,4).accepted

def test_mining_has_no_security_signal_for_benign_examined_cases():
    # The auditor can examine this safe credential surface, but currently
    # emits no structured "examined and ruled benign" record.
    safe_runs = [
        {"manifest": {"discarded": [], "findings": [], "security_auditor": {"examined": ["safe.py"]}}}
        for _ in range(3)
    ]
    bundle = mine(safe_runs)
    assert not [cluster for cluster in bundle.clusters if cluster.agent == "security_auditor"]


def test_mine_ledger_reads_the_real_ledger_and_tags_the_ledger_agent():
    bundle = mine_ledger("docs/false-positive-ledger.md")
    assert len(bundle.clusters) == 6
    assert all(cluster.agent == LEDGER_AGENT for cluster in bundle.clusters)
    assert any(entry.module_path == "FP-001" for cluster in bundle.clusters for entry in cluster.examples)
    assert any(entry.module_path == "FP-005" for cluster in bundle.clusters for entry in cluster.examples)
    assert any(entry.module_path == "FP-006" for cluster in bundle.clusters for entry in cluster.examples)


def test_mine_ledger_ignores_unrelated_tables(tmp_path):
    doc = tmp_path / "ledger.md"
    doc.write_text(
        "# Some other table\n\n| Foo | Bar |\n|---|---|\n| a | b |\n\n"
        "| ID | Source run | Trigger | Root cause | Rule refined | Regression | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| FP-100 | test run | `x()` | duplicate naming proximity | narrow the rule | test_x | Resolved |\n",
        encoding="utf-8",
    )
    bundle = mine_ledger(doc)
    assert len(bundle.clusters) == 1
    assert bundle.clusters[0].examples[0].module_path == "FP-100"


def test_combine_merges_matching_signatures_across_sources():
    first_bundle = mine([run("duplicate naming proximity", "m.py")])
    # A second source sharing the exact same (check, agent, mechanism)
    # signature must fold into one cluster with combined frequency, not
    # appear as two separate size-1 clusters.
    second_bundle = mine([{"manifest": {"discarded": [
        {"reason": "duplicate naming proximity", "module_path": "FP-x", "agent": "bug_investigator",
         "family": "float comparison", "mechanism": "unstripped inline comment"},
    ], "findings": []}}])
    combined = combine(first_bundle, second_bundle)
    assert len(combined.clusters) == 1
    assert combined.clusters[0].frequency == 2


def test_run_held_in_gate_passes_on_the_repository_golden_corpus():
    result = run_held_in_gate(corpus="tests/corpus", min_f1=1.0)
    assert result["passed"], result["below_threshold"]
    assert result["stage"] == "held_in_corpus"
    assert result["by_family"]
