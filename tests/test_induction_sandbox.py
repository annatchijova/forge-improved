import json

from forge import Runtime
from forge.induction import induce_hypothesis


def test_runtime_can_disable_target_induction(tmp_path):
    (tmp_path / "main.py").write_text("import json\ndef load(raw):\n    return json.loads(raw)\n")
    result = Runtime(induction=False).audit(tmp_path, tmp_path / "out")
    verification = json.loads((tmp_path / "out" / "verification-manifest.json").read_text())
    assert verification["induction"] == []
    assert any(item["epistemic_level"] == "PLAUSIBLE HYPOTHESIS" for item in verification["findings"])


def test_induction_synthesizes_a_real_path_for_a_path_annotated_parameter(tmp_path):
    # A Path-typed parameter fed the harness's plain malformed string used to
    # raise AttributeError ('str' object has no attribute 'read_text')
    # before the function's own parsing/exception handling ever ran - a
    # false CONFIRMED BY INDUCTION caused by the wrong argument *type*, not
    # by the hypothesized parsing failure. Found via a self-audit of FORGE's
    # own forge/metrics.py:_python_structure, which already handles this
    # exact malformed-content case correctly.
    (tmp_path / "target.py").write_text(
        "from __future__ import annotations\n"
        "import ast\n"
        "from pathlib import Path\n"
        "def parse_structure(path: Path) -> int:\n"
        "    try:\n"
        "        tree = ast.parse(path.read_text(encoding='utf-8'))\n"
        "    except (OSError, UnicodeDecodeError, SyntaxError):\n"
        "        return 0\n"
        "    return len(tree.body)\n"
    )
    result = induce_hypothesis(tmp_path, "target.py", 6, "The parser call has no nearby exception handling")
    assert result.status == "FALSIFIED", result
    assert "AttributeError" not in result.evidence


def test_induction_still_confirms_a_real_gap_with_a_path_annotated_parameter(tmp_path):
    (tmp_path / "target.py").write_text(
        "from __future__ import annotations\n"
        "import ast\n"
        "from pathlib import Path\n"
        "def parse_structure(path: Path) -> int:\n"
        "    tree = ast.parse(path.read_text(encoding='utf-8'))\n"
        "    return len(tree.body)\n"
    )
    result = induce_hypothesis(tmp_path, "target.py", 5, "The parser call has no nearby exception handling")
    assert result.status == "CONFIRMED BY INDUCTION", result
    assert "SyntaxError" in result.evidence


def test_induction_synthetic_value_for_a_plain_string_parameter_is_unaffected(tmp_path):
    (tmp_path / "target.py").write_text(
        "import json\n"
        "def load(raw):\n"
        "    return json.loads(raw)\n"
    )
    result = induce_hypothesis(tmp_path, "target.py", 3, "The parser call has no nearby exception handling")
    assert result.status == "FALSIFIED"
    assert "JSONDecodeError" in result.evidence


def test_induction_blocks_target_directory_creation_outside_sandbox(tmp_path):
    marker = tmp_path / "outside-sandbox-marker"
    (tmp_path / "target.py").write_text(
        "import json\n"
        "import os\n"
        "from pathlib import Path\n"
        "def load(raw):\n"
        "    os.mkdir(Path(__file__).parent / 'outside-sandbox-marker')\n"
        "    return json.loads(raw)\n"
    )
    result = induce_hypothesis(tmp_path, "target.py", 6, "The parser call has no nearby exception handling")
    assert result.status == "UNDETERMINED", result
    assert "sandbox" in result.detail
    assert not marker.exists()
