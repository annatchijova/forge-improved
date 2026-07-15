import subprocess
from fractions import Fraction

import pytest

def test_finding_rejects_invented_epistemic_level():
    from forge.models import Evidence, Finding
    # This is the exact regression the earlier "epistemic_level='OBSERVED'"
    # bug produced: reusing the category vocabulary as the epistemic level.
    with pytest.raises(ValueError):
        Finding("OBSERVED", "OBSERVED", "x.py", "desc", (Evidence("source", "x.py:1", "detail"),), "reason")

def test_finding_accepts_every_red_team_auditing_epistemic_level():
    from forge.models import Evidence, Finding
    for level in ("CODE FACT", "PLAUSIBLE HYPOTHESIS", "CONFIRMED BY INDUCTION", "FALSIFIED"):
        Finding("OBSERVED", level, "x.py", "desc", (Evidence("source", "x.py:1", "detail"),), "reason")

def test_stack_confidence_is_exact_fraction(tmp_path):
    from forge.detector.stack import detect_stack
    (tmp_path / "a.py").write_text("x = 1\n")
    stack = detect_stack(tmp_path)[0]
    assert stack.confidence == Fraction(55, 100)

def test_git_blame_timeout_degrades_honestly(monkeypatch):
    from forge.report import _blame
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 30)
    monkeypatch.setattr(subprocess, "check_output", timeout)
    assert "timed out" in _blame(".", "missing.py", 1)

def test_held_out_timeout_degrades_honestly(monkeypatch):
    from forge.harness import validation
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 120)
    monkeypatch.setattr(validation.subprocess, "run", timeout)
    result = validation.run_held_out_suite()
    assert result["passed"] is False and result["timed_out"] is True

def test_git_history_timeout_is_bounded_and_reported(tmp_path, monkeypatch):
    from forge.detector import stack

    (tmp_path / "main.py").write_text("print('ok')\n")

    monkeypatch.setattr(stack.subprocess, "check_call", lambda *args, **kwargs: None)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], stack.GIT_HISTORY_TIMEOUT_SECONDS)

    monkeypatch.setattr(stack.subprocess, "check_output", timeout)
    manifest = stack.triage(tmp_path)

    assert manifest.limitations == (
        f"Git history query timed out after {stack.GIT_HISTORY_TIMEOUT_SECONDS} seconds; temporal classification is conservative.",
    )
