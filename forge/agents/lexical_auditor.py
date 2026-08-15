"""Bounded static checks for compiled systems languages (Go, Rust).

Before this agent existed, FORGE recognised Go and Rust well enough to
classify their modules during triage and then analysed neither, so every
finding-free Go repository produced a clean-looking report whose cleanliness
came from having looked at nothing. That is the failure mode this agent exists
to remove.

It is not a compiler front end. Like ``web_auditor`` it scans masked source
through a language pack, and its findings are observations bounded by that
depth: no type information, no scope, no reachability, and no exploitability
claim, because neither language has an induction harness here.
"""
from __future__ import annotations

import os

from forge.agents._lexical import run_lexical_scan
from forge.languages import SYSTEMS_PACKS
from forge.models import AgentScanResult

SYSTEMS_EXTENSIONS = frozenset(
    extension for pack in SYSTEMS_PACKS for extension in pack.extensions
)

#: Families this agent is able to emit, per language. Declared so the audit's
#: detector-scope statement can be specific about what was modelled for Go and
#: Rust instead of implying the Python family list applied to them.
DECLARED_FAMILIES = {
    "Go": (
        "command-injection", "dynamic-evaluation", "hardcoded-credential",
        "parser-boundary", "path-traversal", "sql-injection", "subprocess",
    ),
    "Rust": (
        "command-injection", "hardcoded-credential", "parser-boundary",
        "path-traversal", "sql-injection", "subprocess", "unsafe-block",
    ),
}


def audit(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[AgentScanResult, tuple[str, ...]]:
    return run_lexical_scan("lexical_auditor", SYSTEMS_PACKS, root, eligible)


__all__ = ("DECLARED_FAMILIES", "SYSTEMS_EXTENSIONS", "audit")
