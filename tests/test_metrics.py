import json

from forge import Runtime
import forge.metrics as metrics_module


def test_agent_metrics_do_not_conflate_security_findings_with_bug_investigation(tmp_path):
    (tmp_path / "main.py").write_text("import security\n")
    (tmp_path / "security.py").write_text("password = 'synthetic-secret'\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())

    assert any(item["agent"] == "security_auditor" for item in result.to_dict()["finding_records"])
    assert metrics["agents"]["verification"]["checks_failed"] == 0
    assert metrics["agents"]["abduction"]["patterns_observed"] == 0


def test_metrics_are_layered_and_mark_uncollected_values_honestly(tmp_path):
    (tmp_path / "main.py").write_text("# comment\n\ndef run():\n    return 1\n")
    (tmp_path / "README.md").write_text("synthetic fixture\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_main.py").write_text("def test_run():\n    assert True\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())

    assert metrics["repository"]["files_discovered"] == 3
    assert metrics["repository"]["files_by_language"]["Python"] == 2
    assert metrics["scope"]["coverage"] == {"numerator": 2, "denominator": 2}
    assert metrics["scope"]["discovery_accounting"] == {"numerator": 2, "denominator": 3}
    assert metrics["quality"]["repository_coverage"] == {"covered": 2, "total": 2}
    assert metrics["quality"]["discovery_accounting"] == {"covered": 2, "total": 3}
    assert metrics["reproducibility"]["seed_used"] is None
    assert metrics["audit_trail"]["runtime_events"] > 0
    assert metrics["honest_degradation"]["limitations"]
    assert metrics["agents"]["verification"]["checks_failed"] == 0
    assert result.artifacts["metrics"].endswith("metrics.json")


def test_metrics_reads_loc_once_per_discovered_file(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "notes.md").write_text("fixture\n")
    calls = []
    original = metrics_module._loc

    def counted(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(metrics_module, "_loc", counted)
    Runtime().audit(tmp_path, tmp_path / "out")
    assert len(calls) == 2


def test_identical_fixture_runs_have_identical_finding_digest(tmp_path):
    (tmp_path / "main.py").write_text("import security\n")
    (tmp_path / "security.py").write_text("password = 'synthetic-secret'\n")
    first = Runtime().audit(tmp_path, tmp_path / "out-1")
    second = Runtime().audit(tmp_path, tmp_path / "out-2")
    first_metrics = json.loads((tmp_path / "out-1/metrics.json").read_text())
    second_metrics = json.loads((tmp_path / "out-2/metrics.json").read_text())
    assert first_metrics["findings"]["finding_digest"] == second_metrics["findings"]["finding_digest"]
    assert first.finding_records == second.finding_records
