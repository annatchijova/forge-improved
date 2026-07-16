import json
from forge.models import Evidence, Finding, VerificationManifest
from forge.sealing import write_sealed_manifest
from forge.tiered_report import render_tiered_report, rendered_finding_bytes

def test_all_tiers_preserve_identical_sealed_findings_and_outcomes(tmp_path):
    findings=(
        Finding("OBSERVED", "CODE FACT", "a.py", "credential observed", (Evidence("source", "a.py:1", "password = 'x'"),), "AST assignment check.", "security_auditor", "OBSERVED"),
        Finding("INFERRED", "PROTOCOL_GAP", "b.py", "boundary validation absent", (Evidence("source", "b.py:2", "json.loads(raw)"),), "Boundary contract applies.", "validate-at-the-boundary", "PROTOCOL_GAP"),
    )
    manifest=VerificationManifest("2.0", "0.1.0", "1.0", str(tmp_path), 0, findings, ())
    sealed=tmp_path/"verification-manifest.sealed.json"; write_sealed_manifest(manifest, sealed)
    outputs={mode: render_tiered_report(sealed, mode, tmp_path/f"{mode}.{'json' if mode == 'json' else 'html'}") for mode in ("summary", "standard", "extended", "json")}
    payloads={mode: rendered_finding_bytes(path, mode) for mode, path in outputs.items()}
    assert len(set(payloads.values())) == 1
    projected=[(item["category"], item.get("outcome", "OBSERVED")) for item in json.loads(next(iter(payloads.values())))]
    assert projected == [("OBSERVED", "OBSERVED"), ("INFERRED", "PROTOCOL_GAP")]
    assert "Discarded hypotheses" not in outputs["summary"].read_text()
    assert "Discarded hypotheses" in outputs["standard"].read_text()
    assert "Contract evaluations" in outputs["extended"].read_text()
    assert "background:var(--bg)" in outputs["standard"].read_text()
    assert "--bg:#E3B8B8" in outputs["standard"].read_text()

def test_report_cli_renders_existing_sealed_artifact(tmp_path, monkeypatch, capsys):
    manifest=VerificationManifest("2.0", "0.1.0", "1.0", str(tmp_path), 0, (), ())
    sealed=tmp_path/"sealed.json"; write_sealed_manifest(manifest, sealed)
    from forge.cli import main
    monkeypatch.setattr("sys.argv", ["forge", "report", str(sealed), "--mode", "summary"])
    assert main() == 0
    assert capsys.readouterr().out.strip().endswith(".summary.html")

def test_summary_renderer_escapes_script_text(tmp_path):
    finding=Finding("OBSERVED", "CODE FACT", "evil.py", "<script>alert(1)</script>", (Evidence("source", "evil.py:1", "<script>alert(1)</script>"),), "raw input")
    manifest=VerificationManifest("2.0", "0.1.0", "1.0", str(tmp_path), 0, (finding,), ())
    sealed=tmp_path/"sealed.json"; write_sealed_manifest(manifest, sealed)
    output=render_tiered_report(sealed, "summary", tmp_path/"summary.html")
    html=output.read_text()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_tiered_report_has_review_overview_groups_duplicates_and_exposes_reproduction(tmp_path):
    duplicate = Finding(
        "OBSERVED", "CODE FACT", "payments.py", "money stored as floating point",
        (Evidence("source", "payments.py:17", "total REAL"),), "Integrity check.",
        "integrity_inspector", "OBSERVED", "HIGH",
    )
    manifest = VerificationManifest("2.0", "0.1.0", "1.0", "/workspace/payments", 0, (duplicate, duplicate), ())
    sealed = tmp_path / "sealed.json"; write_sealed_manifest(manifest, sealed)
    (tmp_path / "coverage-report.json").write_text(json.dumps({"files_analyzed": 3, "files_discovered": 5}))

    report = render_tiered_report(sealed, "standard", tmp_path / "standard.html").read_text()

    assert "Review overview" in report
    assert "Sealed records" in report and "Distinct review items" in report
    assert "3 analyzed / 5 discovered" in report
    assert "severity-badge severity-high" in report
    assert "Grouped 2 related sealed records for review." in report
    assert "Review actions" in report and "forge audit /workspace/payments --output forge-run" in report
    assert "href='#overview'" in report and "href='#findings'" in report
    assert "💬 Narrated summary (not verified)" in report


def test_tiered_report_marks_partial_disposition_non_green(tmp_path):
    manifest = VerificationManifest("2.0", "0.1.0", "1.0", str(tmp_path), 0, (), ())
    sealed = tmp_path / "sealed.json"
    write_sealed_manifest(manifest, sealed)
    (tmp_path / "metrics.json").write_text(json.dumps({"audit_disposition": {"status": "PARTIAL_SHARDED"}}))
    output = render_tiered_report(sealed, "summary", tmp_path / "summary.html")
    report = output.read_text()
    assert "status-partial" in report
    assert "PARTIAL_SHARDED" in report
    assert "<p class='status-ok'>" not in report

def test_invalid_finding_outcome_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="invalid finding outcome"):
        Finding("OBSERVED", "CODE FACT", "x.py", "x", (Evidence("source", "x.py:1", "x"),), "test", outcome="invalid_value")
