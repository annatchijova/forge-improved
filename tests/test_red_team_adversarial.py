"""Red-team gate: attacks must not become false passes or false findings."""

import json

import pytest

from forge import Runtime
from forge.hypotheses import _candidates
from forge.induction import induce_hypothesis


def test_attacker_cannot_mutate_a_real_manifest_and_reseal_it(tmp_path):
    (tmp_path / "main.py").write_text("def run(value):\n    return eval(value)\n")
    Runtime().audit(tmp_path, tmp_path / "out")
    verification = tmp_path / "out" / "verification-manifest.json"
    data = json.loads(verification.read_text())
    data["findings"] = []
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="source attestation"):
        Runtime().seal_results(forged, tmp_path / "forged.sealed.json")


def test_package_import_failure_is_not_promoted_to_a_confirmed_bug(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "broken.py").write_text(
        "from .missing_dependency import value\n"
        "def parse(raw):\n"
        "    return raw\n"
    )
    result = induce_hypothesis(tmp_path, "pkg/broken.py", 3, "The parser call `parse(raw)` has no nearby exception handling.")
    assert result.status == "UNDETERMINED"
    assert "could not be loaded" in result.detail


def test_float_serialization_attack_does_not_hide_a_real_decision_float(tmp_path):
    source = (
        "class Result:\n"
        "    def __init__(self, value): self.value = value\n"
        "    def to_dict(self): return {'value': float(self.value)}\n"
        "    def is_bad(self): return float(self.value) > 0.5\n"
    )
    (tmp_path / "result.py").write_text(source)
    from forge.agents.integrity_inspector import inspect
    findings = inspect(tmp_path)
    assert [(item.path, item.line, item.family) for item in findings] == [("result.py", 4, "decision-adjacent-float")]


def test_red_team_fixture_is_not_silently_accepted_after_parser_failure():
    hypotheses, _ = _candidates(
        "fixture.py",
        (
            "import json\n",
            "def analyze(raw):\n",
            "    return json.loads(raw)\n",
        ),
        "Python",
    )
    assert hypotheses


def test_web_language_scope_is_not_counted_as_unanalyzed_when_scanned(tmp_path):
    (tmp_path / "main.py").write_text("import frontend\n")
    (tmp_path / "frontend.ts").write_text("export const value = 1;\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    coverage = result.coverage
    assert "frontend.ts" not in coverage["skipped_reasons"].get("non_python_not_analyzed", ())
    assert coverage["files_analyzed"] == 2
