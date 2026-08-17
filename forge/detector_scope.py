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
    "subprocess", "tamper-evident-audit-chain", "unbounded-copy", "unsafe-block",
    "unsafe-deserialization", "unverified-webhook", "unversioned-serialization",
    "validate-at-the-boundary",
)

# Not every family is modeled for every language. A reader who sees
# `sql-injection` in the list above must not conclude that FORGE looked for it
# in a Java file it never analysed, so the per-language reach is declared
# separately and reported alongside coverage.
FAMILIES_BY_LANGUAGE = {
    "Python": (
        "atomic-state-mutation", "command-injection", "decision-adjacent-float",
        "deterministic-core", "dynamic-evaluation", "hardcoded-credential",
        "honest-degradation", "money-as-float", "parser-boundary",
        "path-traversal", "sql-aggregation-not-materialization", "sql-injection",
        "subprocess", "tamper-evident-audit-chain", "unsafe-deserialization",
        "unverified-webhook", "unversioned-serialization",
        "validate-at-the-boundary",
    ),
    "JavaScript/TypeScript": (
        "dynamic-evaluation", "hardcoded-credential", "parser-boundary",
        "path-traversal", "sql-injection", "subprocess",
    ),
    "Go": (
        "command-injection", "dynamic-evaluation", "hardcoded-credential",
        "parser-boundary", "path-traversal", "sql-injection", "subprocess",
    ),
    "Rust": (
        "command-injection", "hardcoded-credential", "parser-boundary",
        "path-traversal", "sql-injection", "subprocess", "unsafe-block",
    ),
    "Java": (
        "dynamic-evaluation", "hardcoded-credential", "parser-boundary",
        "path-traversal", "sql-injection", "subprocess", "unsafe-deserialization",
    ),
    "C#": (
        "hardcoded-credential", "path-traversal", "sql-injection", "subprocess",
        "unsafe-deserialization",
    ),
    "Ruby": (
        "dynamic-evaluation", "hardcoded-credential", "path-traversal",
        "sql-injection", "subprocess", "unsafe-deserialization",
    ),
    "PHP": (
        "dynamic-evaluation", "hardcoded-credential", "path-traversal",
        "sql-injection", "subprocess", "unsafe-deserialization",
    ),
    "C/C++": (
        "command-injection", "dynamic-evaluation", "hardcoded-credential",
        "path-traversal", "sql-injection", "subprocess", "unbounded-copy",
    ),
}

UNMODELED_DEFECT_CLASSES = (
    "general business logic", "business authorization",
    "concurrency and race conditions", "general type errors",
    "resource lifetime and leak analysis",
    "cross-message temporal and stateful behavioral sequences",
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


def language_scope_statement() -> str:
    """Third boundary: which families were reachable in which language.

    Coverage says which files were read and detector scope says which families
    were modeled. Neither alone stops a reader from assuming the full family
    list applied to every file. This says, per language, what could have been
    found -- and at what analysis depth it could have been found.
    """
    from forge.languages import analysis_depth

    depths = {
        "Python": ".py", "JavaScript/TypeScript": ".ts", "Go": ".go",
        "Rust": ".rs", "Java": ".java", "C#": ".cs", "Ruby": ".rb", "PHP": ".php", "C/C++": ".c",
    }
    parts = [
        f"{language} ({analysis_depth(depths[language])}): " + ", ".join(families)
        for language, families in sorted(FAMILIES_BY_LANGUAGE.items())
    ]
    return (
        "Language scope: an 'ast' language was parsed into a syntax tree; a "
        "'lexical' language was scanned as masked text, with no scope, type or "
        "reachability information. Families reachable per language -- "
        + "; ".join(parts)
        + ". A language absent from this list was not analyzed at all."
    )
