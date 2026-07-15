import json

from forge.models import Evidence, Finding, VerificationManifest
from forge.report import render_report
from forge.sealing import seal_manifest


def test_report_separates_findings_discarded_scope_and_clean_module(tmp_path):
    source = tmp_path / "live.py"
    source.write_text("return eval(value)\n")
    triage = {
        "root": str(tmp_path),
        "modules": [
            {"path": "live.py", "module_class": "CONNECTED_ALIVE"},
            {"path": "old.py", "module_class": "FOSSIL_LOW_RISK"},
        ],
    }
    hypotheses = {
        "audited_modules": ["live.py", "clean.py"],
        "hypotheses": [{"module_path": "live.py", "file_lines": [1], "falsification_test": "Supply a literal."}],
    }
    verification = VerificationManifest(
        "1.0", "0.1.0", "1.0", str(tmp_path), 0,
        (Finding("INFERRED", "PLAUSIBLE HYPOTHESIS", "live.py", "dynamic evaluation", (Evidence("source", "live.py:1", "return eval(value)"),), "AST did not establish safety."),),
        ({"module_path": "clean.py", "reason": "AST proves a benign parser handler."},),
        ("eval/exec",), (),
    )
    triage_path = tmp_path / "triage.json"; triage_path.write_text(json.dumps(triage))
    hypotheses_path = tmp_path / "hypotheses.json"; hypotheses_path.write_text(json.dumps(hypotheses))
    sealed_path = tmp_path / "verification.sealed.json"; sealed_path.write_text(json.dumps(seal_manifest(verification)))
    output = tmp_path / "forge-report.html"
    render_report(triage_path, hypotheses_path, sealed_path, output)
    report = output.read_text()
    assert "FINDINGS" in report and "DISCARDED" in report and "NOT ANALYZED" in report
    assert "No structural risk indicators found" in report
    assert "old.py" in report and "FOSSIL_LOW_RISK" in report
    assert "AST proves a benign parser handler." in report
    assert "Git blame unavailable" in report
    assert "reported_chain_length" in report
    assert "finding-search" in report
    assert "finding-agent" in report
    assert 'data-severity="MEDIUM"' in report
    assert "data-search=" in report
    assert "Showing 1 of 1" in report
    assert 'id="dashboard"' in report
    assert "coverage-dial" in report
    assert "Full metrics and audit telemetry" in report


def test_report_escapes_hostile_content_in_findings_and_module_paths(tmp_path):
    payload = "<script>alert(document.cookie)</script>"
    triage = {
        "root": str(tmp_path),
        "modules": [{"path": "live.py", "module_class": "CONNECTED_ALIVE"}],
    }
    hypotheses = {"audited_modules": ["live.py"], "hypotheses": []}
    verification = VerificationManifest(
        "1.0", "0.1.0", "1.0", str(tmp_path), 0,
        (Finding(
            "INFERRED", "PLAUSIBLE HYPOTHESIS", payload, payload,
            (Evidence("source", "live.py:1", payload),), payload,
        ),),
        ({"module_path": payload, "reason": payload},),
        ("eval/exec",), (),
    )
    triage_path = tmp_path / "triage.json"; triage_path.write_text(json.dumps(triage))
    hypotheses_path = tmp_path / "hypotheses.json"; hypotheses_path.write_text(json.dumps(hypotheses))
    sealed_path = tmp_path / "verification.sealed.json"; sealed_path.write_text(json.dumps(seal_manifest(verification)))
    output = tmp_path / "forge-report.html"
    render_report(triage_path, hypotheses_path, sealed_path, output)
    report = output.read_text()
    assert "<script>alert(document.cookie)</script>" not in report
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in report
