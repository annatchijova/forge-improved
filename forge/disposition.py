"""Deterministic audit disposition, inspired by VIGÍA's abstention gates.

Findings and audit completeness are separate dimensions. A run can contain
valid findings and still abstain from claiming that the whole repository was
covered.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable


_SOURCE_LANGUAGES = {
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".js": "JavaScript",
    ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".c": "C", ".h": "C/C++", ".cpp": "C++", ".cc": "C++",
}


@dataclass(frozen=True)
class AuditDisposition:
    status: str
    reason_code: str
    reason: str
    action_required: str
    evidence_boundary: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def unattested_external_disposition(reasons: Iterable[str]) -> AuditDisposition:
    """Return the shared abstention for preserved, unvouched external findings."""
    return AuditDisposition(
        "ABSTAIN_UNATTESTED_EXTERNAL",
        "UNATTESTED_EXTERNAL_FINDINGS",
        "External findings were preserved, but their analytical provenance was not attested by FORGE.",
        "Review and explicitly operator-attest the external layer before relying on it as an audit result.",
        tuple(reasons),
    )


def determine_disposition(*, coverage: Any, triage: Any, governance: Any,
                          findings: Iterable[Any],
                          degraded_reasons: Iterable[str] = (),
                          contradiction_reasons: Iterable[str] = (),
                          unattested_external_reasons: Iterable[str] = ()) -> AuditDisposition:
    """Return a global status without changing or suppressing findings.

    Policy exclusions, intentionally unanalysed languages, and triage classes
    outside CONNECTED_ALIVE are declared boundaries, not failed evidence.
    Syntax errors and unreadable source remain blocking because Forge cannot
    establish what the source contains.
    """
    degraded = tuple(degraded_reasons)
    contradictions = tuple(contradiction_reasons)
    unattested_external = tuple(unattested_external_reasons)
    skipped = coverage.skipped_reasons
    blocking = {
        key: tuple(value)
        for key, value in skipped.items()
        if key in {"syntax_error", "binary_or_unreadable"} and value
    }
    unsupported_sources: dict[str, int] = {}
    for path in skipped.get("non_python_not_analyzed", ()):
        suffix = str(path).rsplit(".", 1)[-1].lower() if "." in str(path).rsplit("/", 1)[-1] else ""
        language = _SOURCE_LANGUAGES.get(f".{suffix}")
        if language:
            unsupported_sources[language] = unsupported_sources.get(language, 0) + 1
    excluded_modules = tuple(
        item.path for item in triage.modules
        if getattr(item.module_class, "value", item.module_class) != "CONNECTED_ALIVE"
    )
    undetermined = sum(
        state == "UNDETERMINED"
        for states in governance.applicability.values()
        for state in states.values()
    )
    skill_errors = sum(
        state == "ERROR"
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
    if skill_errors:
        boundary += (f"skill_contract: {skill_errors} error result(s)",)
    if unsupported_sources:
        boundary += tuple(f"unsupported_source_language: {language} ({count} file(s))" for language, count in sorted(unsupported_sources.items()))

    if contradictions:
        return AuditDisposition(
            "ABSTAIN_UNDETERMINED",
            "CONTRADICTORY_EVIDENCE",
            "Independent evidence paths conflict; FORGE refuses to collapse them into one conclusion.",
            "Review the contradiction and obtain discriminating evidence.",
            contradictions,
        )
    if unattested_external:
        return unattested_external_disposition(unattested_external)
    if blocking:
        return AuditDisposition(
            "ABSTAIN_INSUFFICIENT_SCOPE",
            "UNVERIFIED_SOURCE_BOUNDARY",
            "The run found evidence, but one or more source boundaries were not verified.",
            "Inspect skipped files and rerun with complete source coverage.",
            boundary,
        )
    if skill_errors:
        return AuditDisposition(
            "ABSTAIN_DEGRADED",
            "GOVERNANCE_SKILL_FAILURE",
            "One or more executable governance skills failed; the remaining evidence is partial.",
            "Repair the failed governance skill and rerun the audit.",
            boundary,
        )
    if degraded:
        return AuditDisposition(
            "ABSTAIN_DEGRADED",
            "SPECIALIZED_AGENT_UNAVAILABLE",
            "One or more specialized agents were unavailable; the remaining evidence is partial.",
            "Restore the unavailable agent and rerun the audit.",
            degraded,
        )
    # An UNDETERMINED governance applicability result means one skill could
    # not confidently classify one module's domain (e.g. a test file with no
    # clear input-boundary signal) - the specialized agents (bug_investigator,
    # security_auditor, integrity_inspector) still ran fully regardless. This
    # is a declared boundary of the same kind as an excluded module or an
    # unsupported source language, not a failure: a single undetermined
    # result out of many (module, skill) pairs previously forced the whole
    # audit to ABSTAIN_UNDETERMINED regardless of how small a fraction it
    # was, which is disproportionate to what actually went unresolved. It
    # still shows up in evidence_boundary below either way, so it is
    # reported, never hidden - it just no longer blocks a completeness claim
    # on its own.
    if excluded_modules or unsupported_sources or undetermined or skipped.get("excluded_by_policy"):
        declared_boundary = boundary
        if skipped.get("excluded_by_policy"):
            declared_boundary += (f"policy_excluded_files: {len(skipped['excluded_by_policy'])} file(s)",)
        return AuditDisposition(
            "COMPLETE_WITHIN_DECLARED_SCOPE",
            "DECLARED_SCOPE_BOUNDARY",
            "The declared source scope was audited; excluded or unsupported material remains outside the engine boundary.",
            "Review the declared boundaries before extending the audit scope.",
            declared_boundary,
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


__all__ = ("AuditDisposition", "determine_disposition", "unattested_external_disposition")
