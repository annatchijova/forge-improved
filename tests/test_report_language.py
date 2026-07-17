import json
from pathlib import Path

from forge import Runtime
from forge.tiered_report import render_tiered_report


_CLEANLINESS_CLAIMS = (
    "no bugs", "no vulnerabilities", "vulnerability-free", "bug-free",
    "is secure", "is safe", "no issues", "clean bill", "guaranteed secure",
    "proves the code is correct", "free of defects", "sin bugs", "sin errores",
    "código seguro", "libre de vulnerabilidades",
)


def test_real_report_qualifies_a_clean_run_by_source_and_detector_scope(tmp_path):
    fixture = Path("tests/corpus/report_language/buggy_but_unmodeled")
    result_dir = tmp_path / "out"
    result = Runtime().audit(fixture, result_dir)
    metrics = json.loads((result_dir / "metrics.json").read_text(encoding="utf-8"))

    # Precondition: these are real logic flaws, but none belongs to a modeled
    # detector family, so this test exercises wording rather than findings.
    assert result.findings == 0
    assert metrics["audit_disposition"]["status"] == "COMPLETE_NO_FINDINGS"

    reports = {
        mode: render_tiered_report(
            result.artifacts["sealed"], mode, result_dir / f"report-language-{mode}.html",
        ).read_text(encoding="utf-8").lower()
        for mode in ("summary", "standard")
    }
    for report in reports.values():
        seal = report.split("<section id='seal'>", 1)[1].split("</section>", 1)[0]
        assert "complete_no_findings" in report
        assert "declared source scope and detector scope" in seal
        assert "parsed;" in seal and "eligible files" in seal and "detector scope" in seal and "discovered" in seal
        assert "detector scope" in report
        assert "general business logic" in report
        assert "business authorization" in report
        assert "concurrency and race conditions" in report
        assert "general type errors" in report
        assert "resource lifetime and leak analysis" in report
        assert not any(claim in report for claim in _CLEANLINESS_CLAIMS)
