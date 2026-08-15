"""Bounded static checks for JavaScript and TypeScript source.

This is intentionally not a JavaScript parser. It scans masked source for a
small set of high-signal boundaries and reports CODE FACTs; it never claims
exploitability without a language-specific induction harness.

The scanning machinery itself now lives in :mod:`forge.languages`, which this
agent drives with the JavaScript/TypeScript pack. The agent keeps its own name
and scope on purpose: its precision and recall baselines are recorded evidence
keyed to ``web_auditor``, and relabelling them to match a refactor would edit
the audit record to suit the code.
"""
from __future__ import annotations

import os

from forge.agents._lexical import run_lexical_scan
from forge.languages import WEB_PACKS
from forge.languages.javascript import PACK
from forge.languages.spec import LexicalFinding
from forge.models import AgentScanResult

WEB_EXTENSIONS = PACK.extensions

#: Retained name for the finding record this agent used to define itself.
WebFinding = LexicalFinding


def audit(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[AgentScanResult, tuple[str, ...]]:
    return run_lexical_scan("web_auditor", WEB_PACKS, root, eligible)


__all__ = ("WEB_EXTENSIONS", "WebFinding", "audit")
