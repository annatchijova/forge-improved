import json
from forge import Runtime
from forge.cli import main as cli_main
from forge.mcp_server import audit_repository
from forge.orchestrator import run_specialized_pipeline

def put(root, name, text):
    path=root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)

def canonical(records):
    return json.dumps(records, sort_keys=True, separators=(",", ":"))

def test_python_api_cli_and_mcp_use_equivalent_runtime_findings(tmp_path, monkeypatch, capsys):
    put(tmp_path, "main.py", "import security\n")
    put(tmp_path, "security.py", "password = 'synthetic-secret'\n")
    api = Runtime().audit(tmp_path, tmp_path/"api-out").to_dict()
    wrapper = run_specialized_pipeline(tmp_path, tmp_path/"wrapper-out")
    monkeypatch.setattr("sys.argv", ["forge", "audit", str(tmp_path), "--output-dir", str(tmp_path/"cli-out")])
    assert cli_main() == 0
    cli=json.loads(capsys.readouterr().out)
    mcp=audit_repository(str(tmp_path), output_dir=str(tmp_path/"mcp-out"))
    assert len({canonical(item["finding_records"]) for item in (api, wrapper, cli, mcp)}) == 1
    assert api["connected_alive"] == wrapper["connected_alive"] == cli["connected_alive"] == mcp["connected_alive"]

def test_mcp_interactive_operations_delegate_to_runtime(tmp_path):
    put(tmp_path, "main.py", "import json\n")
    put(tmp_path, "loader.py", "import json\ndef load(raw):\n    return json.loads(raw)\n")
    from forge.mcp_server import infer_module_domains, list_available_skills, repository_summary, run_skill, triage_repository
    assert triage_repository(str(tmp_path))["ok"]
    assert infer_module_domains(str(tmp_path))["ok"]
    assert repository_summary(str(tmp_path))["ok"]
    # Membership, not skills[0]: asserting on index 0 couples this test to
    # today's single-plugin load order and would break for an unrelated
    # reason the moment a second skill is added ahead of it alphabetically.
    assert any(item["name"] == "validate-at-the-boundary" for item in list_available_skills()["skills"])
    assert run_skill(str(tmp_path), "validate-at-the-boundary")["ok"]

def test_audit_result_reports_discarded_count(tmp_path):
    # eval('1 + 1') generates a hypothesis that module 3 discards via AST
    # proof of benignity, so this fixture must produce discarded > 0.
    put(tmp_path, "main.py", "def run():\n    return eval('1 + 1')\n")
    result = Runtime().audit(tmp_path, tmp_path / "out").to_dict()
    assert "discarded" in result, "AuditResult.to_dict() dropped the discarded count present in the pre-refactor API"
    assert result["discarded"] == 1

def test_audit_survives_a_malformed_skill_manifest(tmp_path):
    skills_root = tmp_path / "skills"
    broken = skills_root / "broken-skill"; broken.mkdir(parents=True)
    (broken / "manifest.json").write_text("{not valid json")
    repo = tmp_path / "repo"; repo.mkdir()
    put(repo, "main.py", "x = 1\n")
    # A malformed skill manifest must not take down the whole audit - the
    # governance-skills layer degrades, the rest of the pipeline still runs.
    result = Runtime(skills_root=skills_root).audit(repo, tmp_path / "out").to_dict()
    assert result["connected_alive"] == 1

def test_audit_survives_a_skill_with_a_manifest_contract_mismatch(tmp_path):
    import json as json_module
    skills_root = tmp_path / "skills"
    bad = skills_root / "mismatched-skill"; bad.mkdir(parents=True)
    (bad / "manifest.json").write_text(json_module.dumps(
        {"name": "mismatched-skill", "version": "1.0", "entrypoint": "contract.py", "class_name": "MismatchedSkill"}
    ))
    (bad / "contract.py").write_text(
        "from forge.models import SkillContract\n"
        "class MismatchedSkill:\n"
        "    contract=SkillContract('WRONG-NAME','1.0',(),(),(),())\n"
        "    def applicability(self, context): return None\n"
        "    def evaluate(self, context): return ()\n"
    )
    repo = tmp_path / "repo"; repo.mkdir()
    put(repo, "main.py", "x = 1\n")
    result = Runtime(skills_root=skills_root).audit(repo, tmp_path / "out").to_dict()
    assert result["connected_alive"] == 1

def test_audit_survives_a_skill_with_a_missing_entrypoint_file(tmp_path):
    import json as json_module
    skills_root = tmp_path / "skills"
    bad = skills_root / "missing-entrypoint"; bad.mkdir(parents=True)
    (bad / "manifest.json").write_text(json_module.dumps(
        {"name": "missing-entrypoint", "version": "1.0", "entrypoint": "does_not_exist.py", "class_name": "X"}
    ))
    repo = tmp_path / "repo"; repo.mkdir()
    put(repo, "main.py", "x = 1\n")
    result = Runtime(skills_root=skills_root).audit(repo, tmp_path / "out").to_dict()
    assert result["connected_alive"] == 1

def test_get_findings_raises_a_clear_error_for_a_missing_run(tmp_path):
    # Runtime.get_findings() lets FileNotFoundError propagate for a missing
    # run rather than swallowing it or returning an empty list that would be
    # indistinguishable from "a real run with zero findings". Regression
    # guard: the message must still name the expected artifact path, not
    # just say "not found" - a direct Python API caller (no MCP wrapper in
    # front of it) has only this message to go on.
    import pytest
    missing = tmp_path / "no-such-run"
    with pytest.raises(FileNotFoundError, match="no-such-run.*verification-manifest.sealed.json"):
        Runtime().get_findings(missing)

def test_cli_rejects_inert_legacy_pipeline_flags(tmp_path, monkeypatch):
    put(tmp_path, "main.py", "x = 1\n")
    import pytest
    monkeypatch.setattr("sys.argv", ["forge", "audit", str(tmp_path), "--hypotheses"])
    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 2
