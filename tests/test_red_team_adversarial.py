"""Red-team gate: attacks must not become false passes or false findings."""

import json
import time

import pytest

from forge import Runtime
from forge.detector.stack import triage
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


def test_induction_worker_blocks_target_import_writes_outside_its_tempdir(tmp_path, monkeypatch):
    sentinel = tmp_path / "must-not-exist.txt"
    monkeypatch.setenv("FORGE_TEST_SENTINEL", str(sentinel))
    (tmp_path / "unsafe_import.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['FORGE_TEST_SENTINEL']).write_text('unsafe')\n"
        "import json\n"
        "def parse(raw):\n"
        "    return json.loads(raw)\n"
    )
    result = induce_hypothesis(tmp_path, "unsafe_import.py", 6, "The parser call `json.loads(raw)` has no nearby exception handling.")
    assert result.status == "UNDETERMINED"
    assert not sentinel.exists()


def test_eval_induction_cannot_escape_via_sandbox_relative_sentinel_symlink(tmp_path, monkeypatch):
    """The fixed eval sentinel must resolve inside the child sandbox.

    A target can create a relative symlink while the worker is in its tempdir.
    The later eval payload follows that link only if the guarded writer accepts
    its resolved target, so this is a direct path-escape probe rather than a
    test of the ordinary in-sandbox sentinel behavior.
    """
    outside = tmp_path / "must-not-exist.txt"
    monkeypatch.setenv("FORGE_TEST_SENTINEL", str(outside))
    (tmp_path / "unsafe_eval.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "def run(expr):\n"
        "    Path('forge-eval-induction-sentinel.txt').symlink_to(os.environ['FORGE_TEST_SENTINEL'])\n"
        "    return eval(expr)\n"
    )
    result = induce_hypothesis(tmp_path, "unsafe_eval.py", 5, "The dynamic evaluation `eval(expr)` has no nearby exception handling.")
    assert result.status == "UNDETERMINED", result
    assert "sandbox" in result.detail.lower()
    assert not outside.exists()


def test_eval_induction_cpu_exhaustion_returns_bounded_undetermined_result(tmp_path):
    (tmp_path / "cpu_eval.py").write_text(
        "def run(expr):\n"
        "    eval(expr)\n"
        "    while True:\n"
        "        pass\n"
    )
    started = time.monotonic()
    result = induce_hypothesis(tmp_path, "cpu_eval.py", 2, "The dynamic evaluation `eval(expr)` has no nearby exception handling.")
    elapsed = time.monotonic() - started
    assert result.status == "UNDETERMINED", result
    assert elapsed < 3.0


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
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "index.ts").write_text("import { value } from './frontend';\n")
    (tmp_path / "frontend.ts").write_text("export const value = 1;\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    coverage = result.coverage
    assert "frontend.ts" not in coverage["skipped_reasons"].get("out_of_detector_scope", ())
    assert coverage["files_analyzed"] == 3


def test_a_python_import_does_not_credit_a_same_named_typescript_module(tmp_path):
    # Connectivity used to be a text tally over import-looking lines, so a
    # Python `import frontend` credited `frontend.ts` with a caller and an
    # orphaned TypeScript module was classified CONNECTED_ALIVE. Imports are
    # resolved per language now: a Python statement cannot reach a TS file.
    (tmp_path / "main.py").write_text("import frontend\n")
    (tmp_path / "frontend.ts").write_text("export const value = 1;\n")
    triage_manifest = triage(tmp_path)
    frontend = next(item for item in triage_manifest.modules if item.path == "frontend.ts")
    assert frontend.caller_count == 0
    assert frontend.module_class.value != "CONNECTED_ALIVE"


def test_generated_build_output_cannot_expand_the_audit_scope(tmp_path):
    (tmp_path / ".next").mkdir()
    (tmp_path / ".next" / "chunk.js").write_text("eval(userInput);\n")
    (tmp_path / "main.py").write_text("x = 1\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    assert result.coverage["files_analyzed"] == 1
    assert ".next/chunk.js" in result.coverage["skipped_reasons"]["excluded_by_policy"]
    assert result.findings == 0


def test_generated_rust_target_output_cannot_expand_the_audit_scope(tmp_path):
    (tmp_path / "target" / "release").mkdir(parents=True)
    (tmp_path / "target" / "release" / "generated.js").write_text("eval(userInput);\n")
    (tmp_path / "main.py").write_text("x = 1\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    assert result.coverage["files_analyzed"] == 1
    assert "target/release/generated.js" in result.coverage["skipped_reasons"]["excluded_by_policy"]
    assert result.findings == 0


def test_python_hypothesis_engine_does_not_parse_typescript_as_python(tmp_path):
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "index.ts").write_text("import { x } from './frontend';\n")
    (tmp_path / "frontend.ts").write_text("export const x = eval(userInput);\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    sealed = json.loads((tmp_path / "out" / "verification-manifest.json").read_text())
    assert not [item for item in sealed["findings"] if item.get("agent") == "bug_investigator"]
    assert [item for item in sealed["findings"] if item.get("agent") == "web_auditor"]
