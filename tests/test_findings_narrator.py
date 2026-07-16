import json

from forge.findings_narrator import READ_ONLY_INPUT_CONTRACT, narrate_sealed_findings
from forge.models import Evidence, Finding, VerificationManifest
from forge.sealing import seal_manifest


def _sealed(tmp_path):
    finding = Finding(
        "OBSERVED", "CODE FACT", "checkout.py", "money amount stored as REAL",
        (Evidence("source", "checkout.py:12", "amount REAL"),),
        "AST detected a monetary SQLite REAL column.", "integrity_inspector",
        "OBSERVED", "MEDIUM",
    )
    manifest = VerificationManifest(
        "2.0", "0.1.0", "1.0", str(tmp_path), 0, (finding,),
        ({"module_path": "hidden.py", "reason": "discarded context must not reach narration"},),
    )
    path = tmp_path / "verification-manifest.sealed.json"
    path.write_text(json.dumps(seal_manifest(manifest)), encoding="utf-8")
    return path


def test_narrator_projects_only_verified_sealed_finding_fields(tmp_path):
    sealed = _sealed(tmp_path)
    (tmp_path / "triage-manifest.json").write_text("secret triage context", encoding="utf-8")
    before = sealed.read_bytes()
    summary = narrate_sealed_findings(sealed)

    assert summary.seal_verified is True
    assert summary.finding_count == 1
    assert summary.presentation_status == "NARRATED_SUMMARY_NOT_VERIFIED"
    assert summary.evidence_authority is False
    assert summary.decision_authority is False
    assert "money amount stored as REAL" in summary.narrative
    assert "discarded context" not in summary.narrative
    assert "secret triage context" not in summary.narrative
    assert summary.input_contract == READ_ONLY_INPUT_CONTRACT
    assert sealed.read_bytes() == before


def test_narrator_refuses_to_summarize_tampered_finding_records(tmp_path):
    sealed = _sealed(tmp_path)
    data = json.loads(sealed.read_text(encoding="utf-8"))
    data["chain"][0]["finding"]["description"] = "tampered finding"
    sealed.write_text(json.dumps(data), encoding="utf-8")

    summary = narrate_sealed_findings(sealed)

    assert summary.seal_verified is False
    assert summary.finding_count == 0
    assert "unavailable" in summary.narrative
    assert "tampered finding" not in summary.narrative
    assert any("hash mismatch" in issue for issue in summary.verification_issues)
