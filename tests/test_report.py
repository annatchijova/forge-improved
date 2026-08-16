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
    assert "Finding origin check" in report
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


def test_report_does_not_style_abstention_as_green_and_links_metrics(tmp_path):
    triage_path = tmp_path / "triage.json"
    triage_path.write_text(json.dumps({"root": str(tmp_path), "modules": []}))
    hypotheses_path = tmp_path / "hypotheses.json"
    hypotheses_path.write_text(json.dumps({"audited_modules": [], "hypotheses": []}))
    sealed_path = tmp_path / "verification.sealed.json"
    sealed_path.write_text(json.dumps(seal_manifest(VerificationManifest("1.0", "0.1.0", "1.0", str(tmp_path), 0, (), ()))))
    output = tmp_path / "forge-report.html"
    render_report(
        triage_path, hypotheses_path, sealed_path, output,
        metrics={"audit_disposition": {"status": "ABSTAIN_DEGRADED", "reason": "bounded scope"}},
    )
    report = output.read_text()
    assert "dashboard-status partial" in report
    assert "ABSTAIN_DEGRADED" in report
    assert "dashboard-status ok" not in report
    assert 'href="metrics.json"' in report
    assert 'Raw metrics' not in report


def test_language_coverage_renders_depth_as_a_table_not_a_python_dict():
    from forge.report import _language_coverage_html

    html = _language_coverage_html({
        "Python": {"analyzed": 12, "abstained": 0, "depth": "ast"},
        "Rust": {"analyzed": 4, "abstained": 1, "depth": "lexical"},
        "Java": {"analyzed": 0, "abstained": 3, "depth": "none"},
    })
    # The escaped `dict` repr this replaced made the report's most important
    # qualifier -- parsed versus merely scanned -- effectively unreadable.
    assert "&#x27;" not in html and "{" not in html
    assert '<table class="data-table">' in html
    assert "depth-ast" in html and "depth-lexical" in html and "depth-none" in html
    # Parsed languages sort ahead of scanned ones, and scanned ahead of
    # unanalysed, so depth reads as a hierarchy of evidence.
    assert html.index("Python") < html.index("Rust") < html.index("Java")
    assert "no scope, type or reachability" in html


def test_language_coverage_handles_a_missing_or_empty_matrix():
    from forge.report import _language_coverage_html

    assert "No language coverage recorded." in _language_coverage_html({})
    assert "No language coverage recorded." in _language_coverage_html(None)


def test_skipped_reasons_explain_each_boundary_distinctly():
    from forge.report import _skipped_reasons_html

    html = _skipped_reasons_html({
        "unsupported_language_not_analyzed": ["Legacy.java"],
        "non_source_not_analyzed": ["README.md"],
        "out_of_detector_scope": ["orphan.ts"],
    })
    # These three are different facts and must not read as one kind of gap.
    assert "engine limit" in html
    assert "not source code" in html
    assert "outside the connected scope" in html


def test_skipped_reasons_truncates_long_file_lists_without_hiding_the_count():
    from forge.report import _skipped_reasons_html

    html = _skipped_reasons_html({"excluded_by_policy": [f"vendor/f{i}.py" for i in range(20)]})
    assert "20" in html
    assert "+14 more" in html
