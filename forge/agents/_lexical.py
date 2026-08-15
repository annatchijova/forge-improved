"""Shared scan plumbing for agents driven by language packs.

The AST agents share ``_scan.prepare_python_scan``; this is the same idea for
the lexical side. One walk, one exclusion policy, one examination ledger, so
two agents covering different languages cannot drift into disagreeing about
what "excluded by scope" means.
"""
from __future__ import annotations

import os
from pathlib import Path

from forge.agent_protocol import mandatory_protocol
from forge.detector.stack import discover_files, exclusion_reason
from forge.languages import LanguagePack, LexicalFinding
from forge.languages.engine import read_source, scan_source
from forge.models import AgentScanResult


def run_lexical_scan(
    agent: str,
    packs: tuple[LanguagePack, ...],
    root: str | os.PathLike[str],
    eligible: set[str] | None = None,
) -> tuple[AgentScanResult, tuple[str, ...]]:
    """Scan every in-scope file owned by ``packs`` and record why each was not.

    ``eligible`` restricts the walk to the triage scope the runtime supplies.
    ``None`` means "no scope filter", which the precision and recall corpora
    rely on to measure a pack in isolation.
    """
    base = Path(root)
    by_extension = {
        extension: pack for pack in packs for extension in pack.extensions
    }
    findings: list[LexicalFinding] = []
    examinations: dict[str, str] = {}
    analyzed: list[str] = []
    for path in discover_files(base, include_excluded=True):
        relative = str(path.relative_to(base))
        reason = exclusion_reason(path, base)
        if reason:
            examinations[relative] = reason
            continue
        if eligible is not None and relative not in eligible:
            examinations[relative] = "excluded_by_scope"
            continue
        pack = by_extension.get(path.suffix.lower())
        if pack is None:
            examinations[relative] = "excluded_by_scope"
            continue
        source, failure = read_source(path)
        if source is None:
            examinations[relative] = failure or "unreadable_file"
            continue
        analyzed.append(relative)
        local = scan_source(pack, relative, source)
        findings.extend(local)
        examinations[relative] = "examined_with_findings" if local else "examined_clean"
    protocol = mandatory_protocol(
        agent,
        tuple(f"{item.family} observed at {item.path}:{item.line}" for item in findings),
        analyzed,
        induction_reason=(
            "This observation came from a masked lexical scan. No induction harness "
            "exists for this language, so the mechanism was not reproduced."
        ),
    )
    return AgentScanResult(tuple(findings), examinations, protocol), tuple(sorted(analyzed))


__all__ = ("run_lexical_scan",)
