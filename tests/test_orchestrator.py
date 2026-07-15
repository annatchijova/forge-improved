from pathlib import Path

import pytest

from forge.orchestrator import run_pipeline


def test_orchestrator_runs_bounded_pipeline(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("def greet():\n    return 'hello'\n")
    result = run_pipeline(repo, tmp_path / "out")
    assert result["connected_alive"] == 1
    assert result["findings"] == 0
    assert (tmp_path / "out" / "forge-report.html").exists()


def test_orchestrator_scope_guard_stops_broad_runs(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("from a import x\n")
    (repo / "a.py").write_text("def x(): return 1\n")
    with pytest.raises(ValueError, match="scope guard"):
        run_pipeline(repo, tmp_path / "out", max_connected=0)


def test_scope_guard_stops_before_downstream_agents(monkeypatch, tmp_path: Path):
    from forge import orchestrator
    from forge.models import TriageManifest

    triage_manifest = TriageManifest("1.0", "0.1.0", str(tmp_path), 0, (), tuple(
        # A minimal record is enough to exercise the post-triage boundary.
        []
    ), {"CONNECTED_ALIVE": 153})
    monkeypatch.setattr(orchestrator, "triage", lambda root: triage_manifest)
    called = []
    monkeypatch.setattr(orchestrator, "generate_hypotheses", lambda _: called.append("hypotheses"))
    with pytest.raises(ValueError, match="153 CONNECTED_ALIVE"):
        orchestrator.run_pipeline(tmp_path, tmp_path / "out", max_connected=100)
    assert called == []
