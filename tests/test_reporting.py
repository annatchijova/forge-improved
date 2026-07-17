import json

from forge import Runtime
from forge.reporting import REPORT_MODES, render_dashboard, render_sharded_dashboard


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


def test_render_sharded_dashboard_links_independent_seals(tmp_path):
    run = tmp_path / "sharded"
    (run / "shards" / "shard-0001").mkdir(parents=True)
    (run / "shards.json").write_text(
        '{"status":"PARTIAL_SHARDED","repository":"/repo","max_connected":2,'
        '"parent_seal":"NOT_GENERATED","shards":[{"index":1,"status":"COMPLETE",'
        '"findings":3,"discarded":1,"paths":["a.py","b.py"]}]}', encoding="utf-8"
    )
    (run / "shards" / "shard-0001" / "findings.jsonl").write_text(
        '{"hash":"same"}\n{"hash":"same"}\n', encoding="utf-8"
    )
    (run / "shards" / "shard-0001" / "report.md").write_text("report", encoding="utf-8")
    output = render_sharded_dashboard(run)
    report = output.read_text(encoding="utf-8")
    assert "navigation and aggregation only" in report
    assert "1" in report and "unique surviving leads by record hash" in report
    assert "1 discarded hypotheses" in report
    assert "shards/shard-0001/report.md" in report
