"""Deterministic audit disposition, inspired by VIGÍA's abstention gates.

Findings and audit completeness are separate dimensions. A run can contain
valid findings and still abstain from claiming that the whole repository was
covered.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable


@dataclass(frozen=True)
class AuditDisposition:
    status: str
    reason_code: str
    reason: str
    action_required: str
    evidence_boundary: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def determine_disposition(*, coverage: Any, triage: Any, governance: Any,
                          findings: Iterable[Any]) -> AuditDisposition:
    """Return a global status without changing or suppressing findings.

    ``non_python_not_analyzed`` is an intentional language boundary for the
    current AST engine. It is disclosed in coverage, but does not itself make
    a Python audit abstain. Other skipped categories represent a lost or
    unverified source boundary and do trigger abstention.
    """
    skipped = coverage.skipped_reasons
    blocking = {
        key: tuple(value)
        for key, value in skipped.items()
        if key != "non_python_not_analyzed" and value
    }
    excluded_modules = tuple(
        item.path for item in triage.modules
        if getattr(item.module_class, "value", item.module_class) != "CONNECTED_ALIVE"
    )
    undetermined = sum(
        state == "UNDETERMINED"
        for states in governance.applicability.values()
        for state in states.values()
    )
    boundary = tuple(
        f"{key}: {len(paths)} file(s)"
        for key, paths in sorted(blocking.items())
    )
    if excluded_modules:
        boundary += (f"out_of_scope_modules: {len(excluded_modules)} module(s)",)
    if undetermined:
        boundary += (f"skill_applicability: {undetermined} undetermined result(s)",)

    if blocking or excluded_modules:
        return AuditDisposition(
            "ABSTAIN_INSUFFICIENT_SCOPE",
            "UNVERIFIED_SOURCE_BOUNDARY",
            "The run found evidence, but one or more source boundaries were not verified.",
            "Inspect skipped files and rerun with complete source coverage.",
            boundary,
        )
    if undetermined:
        return AuditDisposition(
            "ABSTAIN_UNDETERMINED",
            "UNDETERMINED_GOVERNANCE_APPLICABILITY",
            "A governance contract could not determine whether its checks applied.",
            "Resolve applicability and rerun before claiming completeness.",
            boundary,
        )
    if findings:
        return AuditDisposition(
            "COMPLETE_WITH_FINDINGS",
            "AUDIT_SCOPE_VERIFIED",
            "The declared source scope was verified and findings survived the pipeline.",
            "Review findings and their evidence.",
            ("non_python_not_analyzed is an intentional engine boundary",),
        )
    return AuditDisposition(
        "COMPLETE_NO_FINDINGS",
        "AUDIT_SCOPE_VERIFIED",
        "The declared source scope was verified and no findings survived the pipeline.",
        "No action required within the declared scope.",
        ("non_python_not_analyzed is an intentional engine boundary",),
    )


__all__ = ("AuditDisposition", "determine_disposition")
