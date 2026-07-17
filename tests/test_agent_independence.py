import pytest

from forge.agent_independence import AgentIndependenceError, validate_independent_results, write_validation_artifact


ROLES = ("scope_triage", "python_security", "independent_reviewer")


def work(agent):
    return {
        "requested_role": agent,
        "work_product": {
            "observations": [f"{agent} observed source boundary"],
            "hypotheses": [f"{agent} hypothesis"],
            "deductions": [f"{agent} falsifier"],
            "evidence": [f"{agent}.json:1"],
        "decision": ["UNDETERMINED"],
        "adi": [
            {"hypothesis_id": f"{agent}-h1", "stage": "abduction", "statement": "candidate", "evidence": [f"{agent}.json:1"]},
            {"hypothesis_id": f"{agent}-h1", "stage": "deduction", "statement": "falsifier", "evidence": [f"{agent}.json:2"]},
            {"hypothesis_id": f"{agent}-h1", "stage": "induction", "statement": "undetermined", "evidence": [f"{agent}.json:3"]},
        ],
        },
    }


def with_skills(record):
    from forge.agent_protocol import skills_catalog
    record["skills"] = [
        {"skill_name": name, "concrete_action": "reviewed the obligation", "evidence": [f"{source}:1"], "result": "APPLIED"}
        for name, source, _text in skills_catalog()
    ]
    return record


def test_independence_requires_real_work_product_not_protocol_only():
    protocol_only = {role: {"requested_role": role, "adi": [], "skills": [], "scope": []} for role in ROLES}
    with pytest.raises(AgentIndependenceError, match="protocol only"):
        validate_independent_results(protocol_only, ROLES)


def test_independence_rejects_duplicate_work_products():
    records = {role: with_skills(work(role)) for role in ROLES}
    records["independent_reviewer"]["work_product"] = records["scope_triage"]["work_product"]
    with pytest.raises(AgentIndependenceError, match="duplicate"):
        validate_independent_results(records, ROLES)


def test_independence_accepts_distinct_evidence_backed_products():
    result = validate_independent_results({role: with_skills(work(role)) for role in ROLES}, ROLES)
    assert result["status"] == "INDEPENDENCE_VERIFIED"
    assert result["unique_work_products"] == len(ROLES)


def test_independence_requires_hypothesis_specific_adi():
    records = {role: with_skills(work(role)) for role in ROLES}
    records["scope_triage"]["work_product"]["adi"] = []
    with pytest.raises(AgentIndependenceError, match="A-D-I"):
        validate_independent_results(records, ROLES)


def test_independence_rejects_adi_stages_split_or_duplicated_across_hypotheses():
    records = {role: with_skills(work(role)) for role in ROLES}
    records["scope_triage"]["work_product"]["adi"] = [
        {"hypothesis_id": "h1", "stage": "abduction", "statement": "candidate", "evidence": ["a:1"]},
        {"hypothesis_id": "h2", "stage": "deduction", "statement": "falsifier", "evidence": ["a:2"]},
        {"hypothesis_id": "h2", "stage": "induction", "statement": "result", "evidence": ["a:3"]},
    ]
    with pytest.raises(AgentIndependenceError, match="incomplete by hypothesis"):
        validate_independent_results(records, ROLES)
    records = {role: with_skills(work(role)) for role in ROLES}
    records["scope_triage"]["work_product"]["adi"].append(
        {"hypothesis_id": "scope_triage-h1", "stage": "induction", "statement": "duplicate", "evidence": ["a:4"]}
    )
    with pytest.raises(AgentIndependenceError, match="incomplete by hypothesis"):
        validate_independent_results(records, ROLES)


def test_validation_writes_mandatory_closing_artifact(tmp_path):
    results_dir = tmp_path / "agents"
    results_dir.mkdir()
    for role in ROLES:
        import json
        (results_dir / f"{role}.json").write_text(json.dumps(with_skills(work(role))))
    summary = write_validation_artifact(results_dir, ROLES)
    assert summary["status"] == "INDEPENDENCE_VERIFIED"
    assert (results_dir / "agent-independence.json").exists()


def test_independence_rejects_free_applied_claim_for_native_not_applicable_skill():
    from forge.governance.runtime import SkillRun

    records = {role: with_skills(work(role)) for role in ROLES}
    native = SkillRun((), (), {"main.py": {"validate-at-the-boundary": "NOT_APPLICABLE"}}, (), ("validate-at-the-boundary",))
    with pytest.raises(AgentIndependenceError, match="NOT_APPLICABLE"):
        validate_independent_results(records, ROLES, native_skill_run=native)
