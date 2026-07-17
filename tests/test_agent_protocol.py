import json

from forge.agent_protocol import ADI_STAGES, AGENT_NAMES, mandatory_protocol, skills_catalog
from forge.runtime import Runtime


def test_every_policy_skill_is_loaded_into_every_agent_protocol():
    skills = {name for name, _source, _text in skills_catalog()}
    assert len(skills) == 20
    for agent in AGENT_NAMES:
        protocol = mandatory_protocol(agent, ("observed source boundary",), ("main.py",))
        assert {entry.stage for entry in protocol.adi} == set(ADI_STAGES)
        assert {entry.name for entry in protocol.skills} == skills


def test_audit_persists_protocol_for_every_agent(tmp_path):
    (tmp_path / "main.py").write_text("def run(value):\n    return value\n")
    result = Runtime().audit(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out" / "metrics.json").read_text())
    protocols = metrics["agent_protocols"]
    assert set(protocols) == set(AGENT_NAMES)
    assert all({entry["stage"] for entry in item["adi"]} == set(ADI_STAGES) for item in protocols.values())
    assert all(len(item["skills"]) == 20 for item in protocols.values())
    assert result.artifacts["recommendations"].endswith("recommendations.json")


def test_runtime_ledger_projects_executable_skill_evidence(tmp_path):
    (tmp_path / "main.py").write_text(
        "import hashlib\nimport json\ndef seal(data):\n    return hashlib.sha256(json.dumps(data).encode()).hexdigest()\n"
    )
    Runtime().audit(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out" / "metrics.json").read_text())
    skills = {item["name"]: item for item in metrics["agent_protocols"]["security_auditor"]["skills"]}
    assert skills["deterministic-core"]["status"] == "APPLIED"
    assert skills["deterministic-core"]["evidence"]
    assert skills["red-team-auditing"]["status"] == "PROCESS_LEVEL"
