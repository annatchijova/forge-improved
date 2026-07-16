import json
from pathlib import Path

from forge.multi_agent import build_canonical_findings, finalize_multi_agent_run
from forge.sealing import seal_findings, verify_sealed
from forge.agent_protocol import skills_catalog


def test_canonical_findings_preserve_external_and_native_layers():
    records = build_canonical_findings([{"id": "H1", "statement": "external"}], [{"agent": "web_auditor", "description": "native"}])
    assert [item["source_layer"] for item in records] == ["codex_external", "forge_native"]
    assert records[0]["record_id"] == "codex_external:H1"


def test_canonical_finding_set_can_be_sealed_and_verified():
    records = build_canonical_findings([{"id": "H1", "statement": "external"}], [])
    sealed = seal_findings(records, {"finding_set_digest": "test"})
    assert verify_sealed(sealed)["ok"]
    assert sealed["chain"][0]["finding"]["source_layer"] == "codex_external"


def test_finalize_multi_agent_run_writes_one_report_trace_and_canonical_seal(tmp_path):
    run = tmp_path / "run"
    agents = run / "agent-results"
    agents.mkdir(parents=True)
    skills = [{"skill_name": name, "concrete_action": "reviewed obligation", "evidence": [f"{source}:1"], "result": "APPLIED"} for name, source, _text in skills_catalog()]
    for role in ("coordinator", "reviewer"):
        record = {
            "requested_role": role,
            "skills": skills,
            "work_product": {
                "observations": [f"{role} observation"], "hypotheses": [f"{role} hypothesis"],
                "deductions": [f"{role} deduction"], "evidence": [f"{role}.json:1"],
                "decision": ["UNDETERMINED"],
                "adi": [
                    {"hypothesis_id": f"{role}-h1", "stage": stage, "statement": stage, "evidence": [f"{role}.json:1"]}
                    for stage in ("abduction", "deduction", "induction")
                ],
            },
        }
        (agents / f"{role}.json").write_text(json.dumps(record))
    (run / "findings.json").write_text(json.dumps({"findings": [{"id": "H1", "statement": "external", "epistemic_status": "UNDETERMINED"}]}))
    native = seal_findings([{"agent": "native", "description": "native"}], {"schema_version": "native"})
    (run / "verification-manifest.sealed.json").write_text(json.dumps(native))
    result = finalize_multi_agent_run(run, ["coordinator", "reviewer"])
    assert result["status"] == "CANONICAL_FINDINGS_SEALED"
    assert json.loads((run / "agent-independence.json").read_text())["status"] == "INDEPENDENCE_VERIFIED"
    assert verify_sealed(json.loads((run / "verification-manifest.canonical.sealed.json").read_text()))["ok"]
    assert json.loads((run / "report.json").read_text())["finding_set_digest"] == result["finding_set_digest"]
    trace = json.loads((run / "audit-trace.json").read_text())
    assert {event["kind"] for event in trace["events"]} == {"external_agents_validated", "canonical_finding_set_created"}
