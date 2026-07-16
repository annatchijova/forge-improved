from forge.detector.stack import triage
from forge.models import ModuleClass


def test_configured_console_script_is_connected(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project.scripts]\nlegacy = 'package.cli:main'\n"
    )
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "__init__.py").write_text("")
    (tmp_path / "package" / "cli.py").write_text("def main():\n    return 0\n")
    manifest = triage(tmp_path)
    cli = next(item for item in manifest.modules if item.path == "package/cli.py")
    assert cli.module_class is ModuleClass.CONNECTED_ALIVE
    assert any(item.kind == "entry_point" for item in cli.evidence)


def test_scripts_and_tests_are_connected_without_callers(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "scripts" / "migrate.py").write_text("def run():\n    return 0\n")
    (tmp_path / "tests" / "test_api.py").write_text("def test_api():\n    assert True\n")
    manifest = triage(tmp_path)
    classes = {item.path: item.module_class for item in manifest.modules}
    assert classes["scripts/migrate.py"] is ModuleClass.CONNECTED_ALIVE
    assert classes["tests/test_api.py"] is ModuleClass.CONNECTED_ALIVE
