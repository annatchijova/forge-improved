"""Presentation-only prose derived from one verified sealed findings artifact.

This module is deliberately outside the audit decision path.  It accepts only
``verification-manifest.sealed.json`` as input, verifies that artifact before
reading it, and projects a small allowlist of already-sealed finding fields
into deterministic prose.  It never receives triage, hypotheses, metrics,
source files, or the audited repository, and it never writes to the input.

The resulting prose is useful for a human reader, but is not itself evidence
and is not included in the seal.  Reports must label it accordingly.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from forge.io import load_json
from forge.sealing import verify_sealed


READ_ONLY_INPUT_CONTRACT = (
    "Narration reads exactly one sealed verification manifest. It verifies the "
    "manifest before projection, reads only sealed finding fields, and does not "
    "receive audit sidecars, repository source, triage, or discarded hypotheses."
)
_FINDING_FIELDS = (
    "severity",
    "category",
    "epistemic_level",
    "module_path",
    "description",
    "agent",
    "outcome",
)
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class NarratedFindingsSummary:
    """A clearly non-evidentiary presentation layer over sealed findings."""

    seal_verified: bool
    finding_count: int
    narrative: str
    source: str
    presentation_status: str = "NARRATED_SUMMARY_NOT_VERIFIED"
    evidence_authority: bool = False
    decision_authority: bool = False
    authentication_status: str = "NOT_CONFIGURED"
    input_contract: str = READ_ONLY_INPUT_CONTRACT
    verification_issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _project_findings(sealed: dict[str, Any]) -> tuple[dict[str, str], ...]:
    """Copy only display-safe, sealed fields; never expose contextual sidecars."""
    projected: list[dict[str, str]] = []
    for entry in sealed.get("chain", []):
        finding = entry.get("finding", {})
        if not isinstance(finding, dict):
            continue
        projected.append({field: str(finding.get(field, "")) for field in _FINDING_FIELDS})
    return tuple(projected)


def _joined(values: list[str], limit: int = 3) -> str:
    visible = values[:limit]
    suffix = f", and {len(values) - limit} more" if len(values) > limit else ""
    return ", ".join(visible) + suffix


def _narrative(findings: tuple[dict[str, str], ...], authentication_status: str) -> str:
    chain_qualification = (
        "an authenticated sealed finding set"
        if authentication_status == "VERIFIED"
        else "an internally consistent hash-chain finding set"
    )
    if not findings:
        return (
            f"{chain_qualification.capitalize()} contains no surviving findings. "
            "This is a statement about the sealed finding set only; consult the "
            "audit disposition and coverage artifacts before treating it as a "
            "complete audit result."
        )

    severity_counts = Counter(item["severity"].upper() or "UNSPECIFIED" for item in findings)
    severities = [
        f"{severity_counts[severity]} {severity.lower()}"
        for severity in _SEVERITY_ORDER
        if severity_counts[severity]
    ]
    severities += [f"{count} {severity.lower()}" for severity, count in sorted(severity_counts.items()) if severity not in _SEVERITY_ORDER]
    agents = sorted({item["agent"] for item in findings if item["agent"]})
    modules = sorted({item["module_path"] for item in findings if item["module_path"]})
    descriptions = [item["description"] for item in findings if item["description"]]
    highest = next((severity.lower() for severity in _SEVERITY_ORDER if severity_counts[severity]), "unspecified")

    text = (
        f"{chain_qualification.capitalize()} records {len(findings)} surviving finding(s): "
        f"{_joined(severities, limit=len(severities))}. The highest recorded severity is {highest}."
    )
    if authentication_status != "VERIFIED":
        text += " The chain is not externally authenticated."
    if agents:
        text += f" The findings were emitted by {_joined(agents)}."
    if modules:
        text += f" Affected module(s): {_joined(modules)}."
    if descriptions:
        text += f" Reported observations include: {_joined(descriptions)}."
    return text


def narrate_loaded_sealed_findings(sealed: Mapping[str, Any], source: str | Path) -> NarratedFindingsSummary:
    """Narrate one already-loaded artifact, verifying that exact snapshot first."""
    verification = verify_sealed(dict(sealed))
    source_text = str(source)
    authentication_status = str(verification.get("authentication_status", "NOT_CONFIGURED"))
    if not verification.get("ok"):
        issues = tuple(str(issue) for issue in verification.get("issues", ()))
        return NarratedFindingsSummary(
            seal_verified=False,
            finding_count=0,
            narrative=(
                "Narrated summary unavailable because the sealed evidence did not verify. "
                "Inspect the chain-integrity result before reading or relying on any finding text."
            ),
            source=source_text,
            authentication_status=authentication_status,
            verification_issues=issues,
        )

    findings = _project_findings(dict(sealed))
    return NarratedFindingsSummary(
        seal_verified=True,
        finding_count=len(findings),
        narrative=_narrative(findings, authentication_status),
        source=source_text,
        authentication_status=authentication_status,
    )


def narrate_sealed_findings(sealed_path: str | Path) -> NarratedFindingsSummary:
    """Return deterministic prose from a verified sealed findings artifact only.

    A failed seal never receives a finding-level summary: narrating unverified
    records could make altered content look authoritative.  Callers can display
    the returned failure explanation, but must retain the ``not verified`` UI
    label because the prose itself is intentionally outside the seal.
    """
    source = Path(sealed_path)
    sealed = load_json(source, f"sealed findings manifest {source}")
    return narrate_loaded_sealed_findings(sealed, source)


__all__ = (
    "NarratedFindingsSummary",
    "READ_ONLY_INPUT_CONTRACT",
    "narrate_loaded_sealed_findings",
    "narrate_sealed_findings",
)
