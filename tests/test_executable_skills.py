"""Positive and negative contract tests for the executable Class-A skills."""
from __future__ import annotations

from forge.detector.stack import triage
from forge.governance.runtime import run_skills


def _run(tmp_path, source: str):
    (tmp_path / "main.py").write_text("import target\n", encoding="utf-8")
    (tmp_path / "target.py").write_text(source, encoding="utf-8")
    return run_skills(triage(tmp_path))


def _skill_findings(result, name):
    return [finding for finding in result.findings if finding.agent == name]


def test_honest_degradation_reports_silent_fallback_but_not_named_raise(tmp_path):
    result = _run(tmp_path, """\
def load(raw):
    try:
        return raw[\"payload\"]
    except Exception:
        return None
""")
    assert len(_skill_findings(result, "honest-degradation")) == 1
    result = _run(tmp_path, """\
def load(raw):
    try:
        return raw[\"payload\"]
    except KeyError as error:
        raise ValueError(\"artifact payload is required\") from error
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_deterministic_core_requires_canonical_hash_input(tmp_path):
    result = _run(tmp_path, """\
import hashlib
import json
def seal(data):
    return hashlib.sha256(json.dumps(data).encode()).hexdigest()
""")
    assert len(_skill_findings(result, "deterministic-core")) == 1
    result = _run(tmp_path, """\
import hashlib
def canonical_json(data):
    return repr(sorted(data.items()))
def seal(data):
    return hashlib.sha256(canonical_json(data).encode()).hexdigest()
""")
    assert _skill_findings(result, "deterministic-core") == []


def test_deterministic_core_detects_float_and_unordered_payload_paths(tmp_path):
    result = _run(tmp_path, """\
import hashlib
import json
def seal(values):
    payload = {}
    payload[\"score\"] = float(\"0.5\")
    for value in set(values):
        payload[value] = value
    encoded = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(encoded.encode()).hexdigest()
""")
    details = [finding.description for finding in _skill_findings(result, "deterministic-core")]
    assert any("float or division" in detail for detail in details)
    assert any("unordered set/dict" in detail for detail in details)


def test_atomic_state_mutation_requires_visible_transaction(tmp_path):
    result = _run(tmp_path, """\
def replace(conn, row):
    conn.execute(\"INSERT INTO records VALUES (?)\", (row,))
    conn.execute(\"DELETE FROM records WHERE stale = 1\")
""")
    assert len(_skill_findings(result, "atomic-state-mutation")) == 1
    result = _run(tmp_path, """\
def replace(conn, row):
    with conn:
        conn.execute(\"INSERT INTO records VALUES (?)\", (row,))
        conn.execute(\"DELETE FROM records WHERE stale = 1\")
""")
    assert _skill_findings(result, "atomic-state-mutation") == []


def test_sql_aggregation_contract_detects_n_plus_one_but_not_batched_query(tmp_path):
    result = _run(tmp_path, """\
def load(conn, ids):
    for item_id in ids:
        conn.execute(\"SELECT * FROM records WHERE id = ?\", (item_id,))
""")
    assert len(_skill_findings(result, "sql-aggregation-not-materialization")) == 1
    result = _run(tmp_path, """\
def load(conn, ids):
    return conn.execute(\"SELECT * FROM records WHERE id IN (?)\", (ids,))
""")
    assert _skill_findings(result, "sql-aggregation-not-materialization") == []


def test_tamper_evident_contract_requires_previous_hash_link(tmp_path):
    result = _run(tmp_path, """\
def append_audit(ledger, entry):
    ledger.append(entry)
""")
    assert len(_skill_findings(result, "tamper-evident-audit-chain")) == 1
    result = _run(tmp_path, """\
def append_audit(ledger, entry, previous_hash):
    entry[\"prev_hash\"] = previous_hash
    ledger.append(entry)
""")
    assert _skill_findings(result, "tamper-evident-audit-chain") == []


def test_ledger_projects_native_contract_state_and_process_level_policy(tmp_path):
    from forge.agent_protocol import mandatory_protocol

    result = _run(tmp_path, """\
import hashlib
import json
def seal(data):
    return hashlib.sha256(json.dumps(data).encode()).hexdigest()
""")
    protocol = mandatory_protocol("security_auditor", ("checked",), ("target.py",), skill_run=result)
    by_name = {item.name: item for item in protocol.skills}
    assert by_name["deterministic-core"].status == "APPLIED"
    assert by_name["deterministic-core"].evidence
    assert by_name["red-team-auditing"].status == "PROCESS_LEVEL"
