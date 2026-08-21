"""Tests for the SARIF 2.1.0 emitter (forge.sarif).

Covers the epistemic-honest mapping, location parsing, metadata preservation,
and byte-for-byte determinism (same findings -> identical SARIF).
"""

from __future__ import annotations

import json

from forge.models import Evidence, Finding
from forge.sarif import findings_to_sarif, write_sarif


def _confirmed() -> Finding:
    return Finding(
        category="INFERRED",
        epistemic_level="CONFIRMED BY INDUCTION",
        module_path="pkg/_state_store.py",
        description="Unrestricted pickle.loads on stored checkpoint bytes.",
        evidence=(
            Evidence("source", "pkg/_state_store.py:135", "decode_checkpoint_value without allowed_types"),
            Evidence("source", "pkg/_encoding.py:409", "bare pickle.loads", role="derived"),
        ),
        reasoning="Two of three backends pass allowed_types; this one omits it.",
        agent="bug_investigator",
        severity="HIGH",
        controllability="ATTACKER_CONTROLLED",
        exploitability="PLAUSIBLE",
        provenance=("shard-3",),
    )


def _hypothesis() -> Finding:
    return Finding(
        category="INFERRED",
        epistemic_level="PLAUSIBLE HYPOTHESIS",
        module_path="pkg/router.py",
        description="Numeric id with no visible tenant scoping.",
        evidence=(Evidence("source", "pkg/router.py:112", "handler reads id directly"),),
        reasoning="No middleware scoping visible at this layer.",
        severity="MEDIUM",
    )


def test_top_level_shape() -> None:
    sarif = findings_to_sarif([_confirmed()], tool_version="9.9.9")
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "FORGE"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert len(run["results"]) == 1


def test_confirmed_maps_to_fail_and_severity_level() -> None:
    r = findings_to_sarif([_confirmed()])["runs"][0]["results"][0]
    assert r["kind"] == "fail"
    assert r["level"] == "error"  # HIGH severity, and it is confirmed
    assert r["properties"]["epistemic_level"] == "CONFIRMED BY INDUCTION"
    assert r["properties"]["controllability"] == "ATTACKER_CONTROLLED"
    assert r["properties"]["exploitability"] == "PLAUSIBLE"
    assert r["properties"]["provenance"] == ["shard-3"]


def test_hypothesis_never_alarms() -> None:
    # A MEDIUM-severity *hypothesis* must not become a warning; it is review/note.
    r = findings_to_sarif([_hypothesis()])["runs"][0]["results"][0]
    assert r["kind"] == "review"
    assert r["level"] == "note"
    assert r["properties"]["forgeSeverity"] == "MEDIUM"


def test_location_parsing() -> None:
    r = findings_to_sarif([_confirmed()])["runs"][0]["results"][0]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "pkg/_state_store.py"
    assert loc["region"]["startLine"] == 135
    # the derived-role evidence lands in relatedLocations, not locations
    assert r["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "pkg/_encoding.py"


def test_falsified_is_not_applicable() -> None:
    f = Finding(
        category="INFERRED",
        epistemic_level="FALSIFIED",
        module_path="pkg/x.py",
        description="Refuted candidate kept for the audit trail.",
        evidence=(Evidence("source", "pkg/x.py:1", "caller already validates"),),
        reasoning="Benign explanation held.",
    )
    r = findings_to_sarif([f])["runs"][0]["results"][0]
    assert r["kind"] == "notApplicable"
    assert r["level"] == "note"


def test_deterministic() -> None:
    findings = [_confirmed(), _hypothesis()]
    a = json.dumps(findings_to_sarif(findings), sort_keys=True)
    b = json.dumps(findings_to_sarif(findings), sort_keys=True)
    assert a == b


def test_write_sarif_roundtrip(tmp_path) -> None:
    out = write_sarif([_confirmed(), _hypothesis()], tmp_path / "findings.sarif")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 2
    # stable fingerprints present for cross-run identity
    assert "forgeFindingHash/v1" in doc["runs"][0]["results"][0]["partialFingerprints"]


def test_accepts_serialized_dicts() -> None:
    # The emitter must also work on findings already serialized to dict (JSONL).
    finding_dict = {
        "category": "INFERRED",
        "epistemic_level": "CODE FACT",
        "module_path": "pkg/a.py",
        "description": "Direct observation.",
        "evidence": [{"kind": "source", "source": "pkg/a.py:5", "detail": "line 5", "role": "primary"}],
        "reasoning": "read the code",
        "agent": "web_auditor",
        "severity": "LOW",
    }
    r = findings_to_sarif([finding_dict])["runs"][0]["results"][0]
    assert r["kind"] == "fail"  # CODE FACT is confirmed-tier
    assert r["level"] == "note"  # LOW
    assert r["ruleId"] == "forge/web_auditor"
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
