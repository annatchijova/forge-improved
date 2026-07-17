"""Declared analytical scope for reader-facing audit conclusions.

These are the finding families implemented by the built-in deterministic
agents and executable governance contracts. The list is separate from
source-file coverage: inspecting every declared file does not mean every
defect class was analyzed.
"""
from __future__ import annotations


MODELED_DETECTOR_FAMILIES = (
    "atomic-state-mutation", "command-injection", "decision-adjacent-float",
    "deterministic-core", "dynamic-evaluation", "hardcoded-credential",
    "honest-degradation", "money-as-float", "parser-boundary",
    "path-traversal", "sql-aggregation-not-materialization", "sql-injection",
    "subprocess", "tamper-evident-audit-chain", "unsafe-deserialization",
    "unverified-webhook", "unversioned-serialization", "validate-at-the-boundary",
)

UNMODELED_DEFECT_CLASSES = (
    "general business logic", "business authorization",
    "concurrency and race conditions", "general type errors",
    "resource lifetime and leak analysis",
)


def detector_scope_statement() -> str:
    """Human-readable second boundary for every clean scoped conclusion."""
    return (
        "Detector scope: FORGE modeled only these families: "
        + ", ".join(MODELED_DETECTOR_FAMILIES)
        + ". It did not analyze defect classes outside that list, including "
        + ", ".join(UNMODELED_DEFECT_CLASSES)
        + "."
    )
