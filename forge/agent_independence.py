"""Fail-closed validation for externally supplied multi-agent work products.

The native runtime has deterministic specialist workers. A Codex or other
external orchestrator may attach richer agent outputs, but a protocol ledger
alone is not evidence of independent work. This module validates that claim
before a run is presented as multi-agent.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from forge.agent_protocol import skills_catalog


PROTOCOL_ONLY_KEYS = {"requested_role", "native_forge_role", "adi", "scope", "skills"}
REQUIRED_WORK_FIELDS = ("observations", "hypotheses", "deductions", "evidence", "decision", "adi")
REQUIRED_SKILL_FIELDS = ("skill_name", "concrete_action", "evidence", "result")


class AgentIndependenceError(ValueError):
    """Raised when agent outputs do not demonstrate independent work."""


def _text_items(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _fingerprint(work: dict[str, Any]) -> str:
    payload = json.dumps(work, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_adi(agent: str, value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise AgentIndependenceError(f"{agent} has no hypothesis-specific A-D-I ledger")
    by_hypothesis: dict[str, set[str]] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise AgentIndependenceError(f"{agent} A-D-I entry is not an object")
        hypothesis_ids = _text_items(entry.get("hypothesis_id"))
        if len(hypothesis_ids) != 1:
            raise AgentIndependenceError(f"{agent} A-D-I entry has no hypothesis_id")
        by_hypothesis.setdefault(hypothesis_ids[0], set()).add(entry.get("stage"))
        if not _text_items(entry.get("statement")):
            raise AgentIndependenceError(f"{agent} A-D-I entry has no statement")
        if not _text_items(entry.get("evidence")):
            raise AgentIndependenceError(f"{agent} A-D-I entry has no evidence")
    incomplete = {
        hypothesis: sorted({"abduction", "deduction", "induction"} - stages)
        for hypothesis, stages in by_hypothesis.items()
        if stages != {"abduction", "deduction", "induction"}
    }
    if incomplete:
        raise AgentIndependenceError(f"{agent} A-D-I stages are incomplete by hypothesis: {incomplete}")


def _validate_skills(agent: str, value: Any) -> None:
    if not isinstance(value, list):
        raise AgentIndependenceError(f"{agent} skills ledger is not a list")
    expected = {name for name, _source, _text in skills_catalog()}
    actual: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            raise AgentIndependenceError(f"{agent} skill entry is not an object")
        missing = [field for field in REQUIRED_SKILL_FIELDS if field not in item]
        if missing:
            raise AgentIndependenceError(f"{agent} skill entry missing fields: {missing}")
        name = str(item["skill_name"])
        if name in actual:
            raise AgentIndependenceError(f"{agent} has duplicate skill entry: {name}")
        actual[name] = item
        if not _text_items(item.get("concrete_action")):
            raise AgentIndependenceError(f"{agent} skill {name} has no concrete_action")
        if not _text_items(item.get("evidence")):
            raise AgentIndependenceError(f"{agent} skill {name} has no evidence")
        if item.get("result") not in {"APPLIED", "REJECTED", "UNDETERMINED"}:
            raise AgentIndependenceError(f"{agent} skill {name} has invalid result")
    missing = sorted(expected - set(actual))
    extra = sorted(set(actual) - expected)
    if missing or extra:
        raise AgentIndependenceError(f"{agent} skills catalog mismatch; missing={missing}, extra={extra}")


def validate_independent_results(
    results: dict[str, dict[str, Any]],
    required_agents: Iterable[str],
) -> dict[str, Any]:
    """Validate external agent results and return an audit-ready summary.

    Each result must contain a ``work_product`` with concrete observations,
    hypotheses, deductions, evidence, and a decision. A protocol-only record,
    a missing role, or duplicated work product fails closed.
    """
    required = tuple(required_agents)
    missing = sorted(set(required) - set(results))
    if missing:
        raise AgentIndependenceError(f"agent results missing: {missing}")
    fingerprints: dict[str, str] = {}
    for agent in required:
        record = results[agent]
        if not isinstance(record, dict):
            raise AgentIndependenceError(f"{agent} result is not an object")
        if set(record).issubset(PROTOCOL_ONLY_KEYS):
            raise AgentIndependenceError(f"{agent} supplied protocol only; independent work product is missing")
        work = record.get("work_product")
        if not isinstance(work, dict):
            raise AgentIndependenceError(f"{agent} work_product is missing")
        missing_fields = [field for field in REQUIRED_WORK_FIELDS if field not in work]
        if missing_fields:
            raise AgentIndependenceError(f"{agent} work_product missing fields: {missing_fields}")
        if not _text_items(work.get("observations")):
            raise AgentIndependenceError(f"{agent} has no concrete observations")
        if not _text_items(work.get("evidence")):
            raise AgentIndependenceError(f"{agent} has no evidence references")
        if not _text_items(work.get("decision")):
            raise AgentIndependenceError(f"{agent} has no decision")
        _validate_adi(agent, work.get("adi"))
        _validate_skills(agent, record.get("skills"))
        fingerprints[agent] = _fingerprint(work)
    duplicates: dict[str, list[str]] = {}
    for agent, digest in fingerprints.items():
        duplicates.setdefault(digest, []).append(agent)
    repeated = [agents for agents in duplicates.values() if len(agents) > 1]
    if repeated:
        raise AgentIndependenceError(f"duplicate agent work products: {repeated}")
    return {
        "independence_schema_version": "1.0",
        "status": "INDEPENDENCE_VERIFIED",
        "agents": list(required),
        "unique_work_products": len(fingerprints),
        "work_product_digests": fingerprints,
    }


def load_and_validate(directory: str | Path, required_agents: Iterable[str]) -> dict[str, Any]:
    """Load ``*.json`` agent records from a directory and validate them."""
    root = Path(directory)
    if not root.is_dir():
        raise AgentIndependenceError(f"agent results directory does not exist: {root}; expected one JSON file per required role")
    files = sorted(root.glob("*.json"))
    if not files:
        raise AgentIndependenceError(f"agent results directory is empty: {root}; expected one JSON file per required role")
    results: dict[str, dict[str, Any]] = {}
    for path in files:
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            continue
        agent = record.get("agent") or record.get("requested_role")
        if agent:
            results[str(agent)] = record
    return validate_independent_results(results, required_agents)


def write_validation_artifact(directory: str | Path, required_agents: Iterable[str], destination: str | Path | None = None) -> dict[str, Any]:
    """Validate results and persist the mandatory multi-agent closing artifact."""
    summary = load_and_validate(directory, required_agents)
    target = Path(destination) if destination is not None else Path(directory) / "agent-independence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**summary, "artifact": str(target)}


__all__ = ("AgentIndependenceError", "load_and_validate", "validate_independent_results", "write_validation_artifact")
