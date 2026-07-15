from pathlib import Path
from forge.detector.stack import triage
from forge.models import ModuleClass

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
