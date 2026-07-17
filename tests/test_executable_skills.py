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
def load_artifact(raw):
    try:
        return raw[\"payload\"]
    except Exception:
        return None
""")
    assert len(_skill_findings(result, "honest-degradation")) == 1
    result = _run(tmp_path, """\
def load_artifact(raw):
    try:
        return raw[\"payload\"]
    except KeyError as error:
        raise ValueError(\"artifact payload is required\") from error
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_does_not_exonerate_logged_default_return(tmp_path):
    result = _run(tmp_path, """\
import logging

def to_signal(raw):
    try:
        return raw["payload"]
    except Exception:
        logging.warning("payload unavailable")
        return None
""")
    findings = _skill_findings(result, "honest-degradation")
    assert len(findings) == 1
    assert "without raising or marking degraded state" in findings[0].description


def test_honest_degradation_reports_logged_drop_continue_without_degraded_state(tmp_path):
    result = _run(tmp_path, """\
import logging

def run_vigia(rows):
    signals = []
    for row in rows:
        try:
            signals.append(SignalOutput(description=row["description"]))
        except TypeError:
            logging.warning("Invalid signal ignored")
            continue
    return verdict_from(signals)
""")
    findings = _skill_findings(result, "honest-degradation")
    assert len(findings) == 1
    assert "output silently reduced" in findings[0].description

    result = _run(tmp_path, """\
import logging

def run_vigia(rows):
    signals = []
    degraded = False
    for row in rows:
        try:
            signals.append(SignalOutput(description=row["description"]))
        except TypeError:
            logging.warning("Invalid signal ignored")
            degraded = True
            continue
    return {"verdict": verdict_from(signals), "degraded": degraded}
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_accepts_sentinel_and_error_accumulator(tmp_path):
    result = _run(tmp_path, """\
def build_signals(rows):
    signals = []
    for row in rows:
        try:
            signals.append(Signal(row["tool"], row["value"]))
        except Exception as exc:
            signals.append(unanalyzed_marker(row, exc))
    return signals
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def analyze_records(rows):
    findings = []
    unparsed = 0
    for row in rows:
        try:
            findings.append(parse_record(row))
        except ValueError:
            unparsed += 1
            continue
    return {"findings": findings, "unparsed_files": unparsed}
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def build_signals(rows):
    signals = []
    errors = []
    for row in rows:
        try:
            signals.append(Signal(row["tool"], row["value"]))
        except Exception as exc:
            errors.append((row, exc))
            continue
    return signals, errors
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_reports_stage_swallow_but_not_recorded_skip(tmp_path):
    result = _run(tmp_path, """\
def analyze(signal):
    try:
        caie = run_caie(signal.metadata)
    except Exception:
        logger.warning("CAIE failed non-blocking")
        caie = None
    return build_result(signal, caie)
""")
    findings = _skill_findings(result, "honest-degradation")
    assert len(findings) == 1
    assert "stage result" in findings[0].description

    result = _run(tmp_path, """\
def analyze(signal):
    result_flags = {}
    try:
        caie = run_caie(signal.metadata)
    except Exception as exc:
        caie = None
        result_flags["caie_skipped"] = str(exc)
    return build_result(signal, caie, result_flags)
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_does_not_mark_optional_field_or_cleanup(tmp_path):
    result = _run(tmp_path, """\
def profile(data):
    try:
        nickname = data["nickname"]
    except KeyError:
        nickname = None
    return {"nickname": nickname}
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def get_nickname(data):
    try:
        return data["nickname"]
    except KeyError:
        return None
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def parse_tmp(tmp):
    try:
        return load(tmp)
    finally:
        os.unlink(tmp)
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def inspect_source(source):
    try:
        return ast.parse(source)
    except SyntaxError:
        return None
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_stage_prefixes_and_parse_exemption_are_structural(tmp_path):
    result = _run(tmp_path, """\
def token_count(raw):
    try:
        return int(raw)
    except Exception:
        return None
""")
    assert _skill_findings(result, "honest-degradation") == []

    result = _run(tmp_path, """\
def parse_untrusted(raw):
    try:
        return ast.parse(raw)
    except Exception:
        return None
""")
    assert len(_skill_findings(result, "honest-degradation")) == 1

    result = _run(tmp_path, """\
def inspect_payload(raw):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None
""")
    assert _skill_findings(result, "honest-degradation") == []


def test_honest_degradation_recognizes_returned_unanalyzed_signal_and_drop_ledger(tmp_path):
    result = _run(tmp_path, """\
class Engine:
    def to_signal(self, raw):
        try:
            return convert(raw)
        except Exception as exc:
            self._signal_drops.append(str(exc))
            return self._unanalyzed_signal("engine", str(exc))
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
