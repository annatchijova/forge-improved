import json

from forge import Runtime
from forge.reporting import REPORT_MODES, render_dashboard


def test_render_dashboard_generates_main_report_and_all_modes(tmp_path):
    (tmp_path / "main.py").write_text("def run(value):\n    return float(value)\n")
    result = Runtime().audit(tmp_path, tmp_path / "run")

    paths = render_dashboard(tmp_path / "run")

    assert set(REPORT_MODES) <= {key.removeprefix("report_") for key in paths if key != "report"}
    assert paths["report"].endswith("forge-report.html")
    assert "Repository intelligence" in (tmp_path / "run/forge-report.html").read_text()
    sealed_findings = json.loads((tmp_path / "run/verification-manifest.sealed.json").read_text())["chain"]
    for mode in REPORT_MODES:
        output = tmp_path / "run" / f"forge-report-{mode}.{'json' if mode == 'json' else 'html'}"
        assert output.is_file()
        if mode == "json":
            assert json.loads(output.read_text())["chain"] == sealed_findings
