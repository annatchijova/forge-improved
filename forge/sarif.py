"""SARIF 2.1.0 emitter for FORGE findings.

Additive output layer that renders :class:`forge.models.Finding` records as
SARIF so results are consumable by GitHub code scanning, CI, and SARIF viewers.

Design boundary (mirrors "narrative beside the seal, never inside it"):
SARIF is a *rendering* of findings, never an input to the sealed evidence
chain. Emitting SARIF neither reads nor mutates the seal; it must not change any
value that gets sealed. Keep it deterministic — no wall-clock, stable ordering,
stable fingerprints — so the same findings always produce byte-identical SARIF.

Epistemic honesty is preserved in SARIF's own vocabulary rather than flattened
into a severity number:

* ``CONFIRMED BY INDUCTION`` / ``CODE FACT``            -> ``result.kind = "fail"``
* ``PLAUSIBLE HYPOTHESIS`` / ``PROTOCOL_GAP`` /
  ``DESIGN_INCONSISTENCY`` / ``UNDETERMINED``           -> ``result.kind = "review"``
* ``FALSIFIED`` / ``NOT_APPLICABLE``                    -> ``result.kind = "notApplicable"``

An un-confirmed finding never receives an alarming SARIF ``level``: only
confirmed findings map their ``severity`` onto ``error``/``warning``; every
hypothesis is emitted as ``note`` + ``kind="review"`` so a reviewer is not
misled into treating a candidate as a proven defect. The full forge metadata
(``epistemic_level``, ``category``, ``reasoning``, ``controllability``,
``exploitability``, ``provenance``, ``occurrences``) is carried verbatim in
``result.properties``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "FORGE"
_TOOL_URI = "https://github.com/annatchijova/forge"

# epistemic_level -> SARIF result.kind
_CONFIRMED = frozenset({"CONFIRMED BY INDUCTION", "CODE FACT"})
_REVIEW = frozenset({"PLAUSIBLE HYPOTHESIS", "PROTOCOL_GAP", "DESIGN_INCONSISTENCY", "UNDETERMINED"})
_NOT_APPLICABLE = frozenset({"FALSIFIED", "NOT_APPLICABLE"})

# severity -> SARIF result.level (only applied to CONFIRMED findings)
_SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "INFORMATIONAL": "note",
}


def _get(finding: Any, name: str, default: Any = None) -> Any:
    """Read a field from a Finding dataclass or a serialized dict."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _evidence_items(finding: Any) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for ev in _get(finding, "evidence", ()) or ():
        items.append(
            {
                "kind": str(_get(ev, "kind", "") or ""),
                "source": str(_get(ev, "source", "") or ""),
                "detail": str(_get(ev, "detail", "") or ""),
                "role": str(_get(ev, "role", "primary") or "primary"),
            }
        )
    return items


def _kind(epistemic_level: str) -> str:
    if epistemic_level in _CONFIRMED:
        return "fail"
    if epistemic_level in _NOT_APPLICABLE:
        return "notApplicable"
    return "review"  # every unconfirmed hypothesis, incl. unknown levels, is a review item


def _level(epistemic_level: str, severity: str) -> str:
    # Only confirmed findings may raise an alarming level; hypotheses stay "note".
    if epistemic_level in _CONFIRMED:
        return _SEVERITY_LEVEL.get(str(severity).upper(), "warning")
    return "note"


def _split_source(source: str) -> tuple[str, int | None]:
    """Split an Evidence ``source`` of the form ``module/path:line``."""
    path, sep, line_text = source.rpartition(":")
    if sep and line_text.isdigit() and path:
        return path, int(line_text)
    return source, None


def _location(source: str, detail: str) -> dict[str, Any]:
    path, line = _split_source(source)
    physical: dict[str, Any] = {"artifactLocation": {"uri": path}}
    if line is not None:
        physical["region"] = {"startLine": line}
    loc: dict[str, Any] = {"physicalLocation": physical}
    if detail:
        loc["message"] = {"text": detail}
    return loc


def _fingerprint(finding: Any, primary_source: str) -> str:
    """Stable per-finding fingerprint for cross-run identity / dedup."""
    parts = [
        str(_get(finding, "category", "")),
        str(_get(finding, "epistemic_level", "")),
        str(_get(finding, "module_path", "")),
        primary_source,
        str(_get(finding, "description", "")),
    ]
    # Unit-separator delimiter: unambiguous field boundary, cannot occur in the
    # source paths / descriptions being joined, so distinct findings never collide.
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _rule_id(finding: Any) -> str:
    agent = str(_get(finding, "agent", "forge") or "forge")
    return f"forge/{agent}"


def finding_to_result(finding: Any) -> dict[str, Any]:
    epistemic_level = str(_get(finding, "epistemic_level", "UNDETERMINED") or "UNDETERMINED")
    severity = str(_get(finding, "severity", "MEDIUM") or "MEDIUM")
    evidence = _evidence_items(finding)
    primaries = [e for e in evidence if e["role"] == "primary"] or evidence

    locations = [_location(e["source"], e["detail"]) for e in primaries if e["source"]]
    related = [_location(e["source"], e["detail"]) for e in evidence if e not in primaries and e["source"]]
    primary_source = primaries[0]["source"] if primaries else ""

    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "kind": _kind(epistemic_level),
        "level": _level(epistemic_level, severity),
        "message": {"text": str(_get(finding, "description", "") or "")},
        "partialFingerprints": {"forgeFindingHash/v1": _fingerprint(finding, primary_source)},
        "properties": {
            "epistemic_level": epistemic_level,
            "category": str(_get(finding, "category", "") or ""),
            "agent": str(_get(finding, "agent", "") or ""),
            "outcome": str(_get(finding, "outcome", "") or ""),
            "forgeSeverity": severity,
            "controllability": str(_get(finding, "controllability", "UNDETERMINED") or "UNDETERMINED"),
            "exploitability": str(_get(finding, "exploitability", "NOT_ASSESSED") or "NOT_ASSESSED"),
            "reasoning": str(_get(finding, "reasoning", "") or ""),
            "provenance": [str(p) for p in (_get(finding, "provenance", ()) or ())],
            "occurrences": [str(o) for o in (_get(finding, "occurrences", ()) or ())],
        },
    }
    if locations:
        result["locations"] = locations
    if related:
        result["relatedLocations"] = related
    return result


def _rules(findings: list[Any]) -> list[dict[str, Any]]:
    seen: dict[str, str] = {}
    for f in findings:
        rid = _rule_id(f)
        if rid not in seen:
            seen[rid] = str(_get(f, "agent", "forge") or "forge")
    return [
        {
            "id": rid,
            "name": agent,
            "shortDescription": {"text": f"FORGE finding surfaced by the {agent} agent."},
        }
        for rid, agent in sorted(seen.items())
    ]


def findings_to_sarif(findings: list[Any], *, tool_version: str = "0.1.0") -> dict[str, Any]:
    """Render FORGE findings as a SARIF 2.1.0 log (deterministic; no wall-clock)."""
    results = [finding_to_result(f) for f in findings]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "version": tool_version,
                        "organization": "Anna Tchijova",
                        "rules": _rules(findings),
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


def write_sarif(findings: list[Any], path: str | Path, *, tool_version: str = "0.1.0") -> Path:
    """Write ``findings.sarif`` deterministically beside the run's other artifacts."""
    out = Path(path)
    payload = json.dumps(findings_to_sarif(findings, tool_version=tool_version), indent=2, sort_keys=True)
    out.write_text(payload + "\n", encoding="utf-8")
    return out
