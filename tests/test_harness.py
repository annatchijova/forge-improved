from forge.harness.mining import mine
from forge.harness.proposal import propose
from forge.harness.validation import validate
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
