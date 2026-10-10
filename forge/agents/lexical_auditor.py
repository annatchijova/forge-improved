"""Bounded static checks for every lexically-scanned language except the web.

Before this agent existed, FORGE recognised Go, Rust, Java and C# well enough
to classify their modules during triage and then analysed none of them, so a
finding-free Go or Java repository produced a clean-looking report whose
cleanliness came from having looked at nothing. That is the failure mode this
agent exists to remove.

It is not a compiler front end. Like ``web_auditor`` it scans masked source
through a language pack, and its findings are observations bounded by that
depth: no type information, no scope, no reachability, and no exploitability
claim, because none of these languages has an induction harness here.

The split from ``web_auditor`` is by agent ownership, not by a taxonomy claim
about the languages. ``web_auditor`` keeps JavaScript/TypeScript because its
precision and recall baselines are recorded evidence keyed to that agent name.
"""
from __future__ import annotations

import os

from forge.agents._lexical import run_lexical_scan
from forge.detector_scope import FAMILIES_BY_LANGUAGE
from forge.languages import LEXICAL_AUDITOR_PACKS
from forge.models import AgentScanResult

SYSTEMS_EXTENSIONS = frozenset(
    extension for pack in LEXICAL_AUDITOR_PACKS for extension in pack.extensions
)

#: Families this agent can emit, per language. Declared so the audit's language
#: scope statement can be specific about what was modelled for each language
#: instead of implying the Python family list applied to all of them. Derived
#: from the shared registry so the two cannot drift apart.
DECLARED_FAMILIES = {
    pack.name: FAMILIES_BY_LANGUAGE.get(pack.name, ())
    for pack in LEXICAL_AUDITOR_PACKS
}


def audit(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[AgentScanResult, tuple[str, ...]]:
    return run_lexical_scan("lexical_auditor", LEXICAL_AUDITOR_PACKS, root, eligible)


__all__ = ("DECLARED_FAMILIES", "SYSTEMS_EXTENSIONS", "audit")
