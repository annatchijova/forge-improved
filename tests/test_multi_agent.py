import json
from pathlib import Path

from forge.multi_agent import build_canonical_findings, finalize_multi_agent_run, operator_attest_external_findings
from forge.sealing import seal_findings, verify_sealed
from forge.agent_protocol import skills_catalog


def test_canonical_findings_preserve_external_and_native_layers():
    records = build_canonical_findings([{"id": "H1", "statement": "external"}], [{"agent": "web_auditor", "description": "native"}])
    assert [item["source_layer"] for item in records] == ["codex_external", "forge_native"]
    assert [item["analytic_provenance"] for item in records] == ["UNATTESTED", "FORGE_NATIVE"]
    assert records[0]["record_id"] == "codex_external:H1"


def test_canonical_finding_set_can_be_sealed_and_verified():
    records = build_canonical_findings([{"id": "H1", "statement": "external"}], [])
    sealed = seal_findings(records, {"finding_set_digest": "test"})
    assert verify_sealed(sealed)["ok"]
    assert sealed["chain"][0]["finding"]["source_layer"] == "codex_external"


def _write_agent_results(run):
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


def test_finalize_multi_agent_run_labels_fabricated_external_findings_and_abstains(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_ATTESTATION_KEY", "test-only-persistent-attestation-key")
    run = tmp_path / "run"
    _write_agent_results(run)
    (run / "findings.json").write_text(json.dumps({"findings": [{"id": "H1", "statement": "external", "epistemic_status": "UNDETERMINED"}]}))
    native = seal_findings([{"agent": "native", "description": "native"}], {"schema_version": "native"})
    (run / "verification-manifest.sealed.json").write_text(json.dumps(native))
    result = finalize_multi_agent_run(run, ["coordinator", "reviewer"])
    assert result["status"] == "ABSTAIN_UNATTESTED_EXTERNAL"
    assert result["disposition"]["reason_code"] == "UNATTESTED_EXTERNAL_FINDINGS"
    assert result["analytic_provenance"]["codex_external"] == "UNATTESTED"
    assert json.loads((run / "agent-independence.json").read_text())["status"] == "INDEPENDENCE_VERIFIED"
    canonical_verification = verify_sealed(json.loads((run / "verification-manifest.canonical.sealed.json").read_text()))
    assert canonical_verification["ok"]
    assert canonical_verification["attestation_status"] == "VERIFIED"
    findings = json.loads((run / "findings.json").read_text())
    report = json.loads((run / "report.json").read_text())
    sealed = json.loads((run / "verification-manifest.canonical.sealed.json").read_text())
    assert findings["finding_set_digest"] == result["finding_set_digest"]
    assert report["finding_set_digest"] == result["finding_set_digest"]
    assert sealed["manifest"]["finding_set_digest"] == result["finding_set_digest"]
    assert sealed["manifest"]["disposition"]["status"] == "ABSTAIN_UNATTESTED_EXTERNAL"
    assert sealed["chain"][0]["finding"]["analytic_provenance"] == "UNATTESTED"
    assert result["finding_set_digest"] in (run / "report.md").read_text()
    report_markdown = (run / "report.md").read_text()
    assert "Canonical assembly attestation: `VERIFIED`" in report_markdown
    assert "External analytical provenance: `UNATTESTED`" in report_markdown
    trace = json.loads((run / "audit-trace.json").read_text())
    assert {event["kind"] for event in trace["events"]} == {"external_agents_validated", "canonical_finding_set_created"}


def test_explicit_operator_attestation_can_vouch_for_external_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_ATTESTATION_KEY", "test-only-persistent-attestation-key")
    run = tmp_path / "run"
    _write_agent_results(run)
    external = operator_attest_external_findings({"findings": [{"id": "H1", "statement": "reviewed external"}]})
    (run / "findings.json").write_text(json.dumps(external))
    native = seal_findings([{"agent": "native", "description": "native"}], {"schema_version": "native"})
    (run / "verification-manifest.sealed.json").write_text(json.dumps(native))
    result = finalize_multi_agent_run(run, ["coordinator", "reviewer"])
    assert result["status"] == "CANONICAL_FINDINGS_SEALED"
    assert result["analytic_provenance"]["codex_external"] == "OPERATOR_ATTESTED"
    assert result["disposition"] is None


def test_finalizer_rejects_a_native_persistent_attestation_that_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_ATTESTATION_KEY", "test-only-persistent-attestation-key")
    run = tmp_path / "run"
    _write_agent_results(run)
    (run / "findings.json").write_text(json.dumps({"findings": []}))
    native = seal_findings([{"agent": "native", "description": "native"}], {"schema_version": "native"})
    native["source_attestation"] = "forged"
    (run / "verification-manifest.sealed.json").write_text(json.dumps(native))
    import pytest
    with pytest.raises(ValueError, match="native sealed artifact is not verified"):
        finalize_multi_agent_run(run, ["coordinator", "reviewer"])
