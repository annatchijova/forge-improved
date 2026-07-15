from pathlib import Path
from forge.detector.stack import triage
from forge.models import ModuleClass
from forge.hypotheses import generate_hypotheses

def test_python_repo_detects_stack_and_classes(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "main.py").write_text("from live import run\n")
    (tmp_path / "live.py").write_text("def run(): return 1\n")
    (tmp_path / "old.py").write_text("def verdict(x): return x\n")
    manifest = triage(tmp_path)
    assert any(s.name == "Python" for s in manifest.stacks)
    assert {m.module_class for m in manifest.modules} >= {ModuleClass.CONNECTED_ALIVE, ModuleClass.FOSSIL_HIGH_RISK}

def test_javascript_repo_is_not_python_overfit(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"jest"}}')
    (tmp_path / "index.js").write_text("const util = require('./util'); module.exports = util;\n")
    (tmp_path / "util.js").write_text("module.exports = () => 1;\n")
    manifest = triage(tmp_path)
    assert any(s.name == "JavaScript" for s in manifest.stacks)
    assert not any(s.name == "Python" for s in manifest.stacks)

def test_hypotheses_are_construct_specific_and_falsifiable(tmp_path: Path):
    fixtures = {
        "subprocess.py": "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd)\n",
        "parser.py": "import json\ndef load(raw):\n    return json.loads(raw)\n",
        "score.py": "def score(value):\n    return 'high' if score(value) > 0.1 else 'low'\n",
        "dynamic.py": "def run(expr):\n    return eval(expr)\n",
    }
    texts = []
    for name, body in fixtures.items():
        case = tmp_path / name
        case.mkdir()
        (case / "main.py").write_text(body)
        result = generate_hypotheses(triage(case))
        assert result.hypotheses
        hypothesis = result.hypotheses[0]
        assert hypothesis.falsification_test.strip() and hypothesis.file_lines
        texts.append(hypothesis.description)
    assert len(set(texts)) == 4
    assert "subprocess.run" in texts[0]
    assert "json.loads" in texts[1]
    assert "float" in texts[2]
    assert "eval" in texts[3]

def test_boring_connected_module_gets_no_forced_hypotheses(tmp_path: Path):
    (tmp_path / "main.py").write_text("def greet():\n    return 'hello'\n")
    generated = generate_hypotheses(triage(tmp_path))
    assert generated.hypotheses == ()

def test_keyword_in_safe_context_does_not_fire(tmp_path: Path):
    (tmp_path / "main.py").write_text("# parse and subprocess are discussed here\nimport subprocess\ndef run():\n    try:\n        return subprocess.run(['trusted-tool'], check=True)\n    except subprocess.SubprocessError as exc:\n        raise RuntimeError('tool failed') from exc\n")
    generated = generate_hypotheses(triage(tmp_path))
    assert generated.hypotheses == ()
