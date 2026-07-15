"""Module 2: abductive, read-before-reason hypothesis generation."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from forge.models import HypothesesManifest, Hypothesis, ModuleClass, TriageManifest


def _lines(path: Path) -> tuple[str, ...]:
    # Reading the actual source is a hard precondition for generation.
    return tuple(path.read_text(encoding="utf-8", errors="replace").splitlines())


def _code_before_comment(line: str) -> str:
    """Return code before an inline comment, preserving '#' inside strings."""
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == "#" and quote is None:
            return line[:index]
    return line


def _candidates(module_path: str, source: tuple[str, ...], language: str) -> list[Hypothesis]:
    candidates: list[tuple[str, int, str]] = []
    for number, line in enumerate(source, 1):
        stripped = _code_before_comment(line).strip()
        # Ignore comments and strings that merely mention a risk word.
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\b(subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system)\s*\(", stripped):
            if not any("try:" in source[i] for i in range(max(0, number - 4), number)):
                candidates.append((f"The dynamic command invocation `{stripped}` at {module_path}:{number} may pass attacker-controlled arguments without an enclosing failure boundary.", number, f"Invoke this call with a harmless invalid executable and a shell metacharacter fixture; an explicit exception path with no command execution falsifies the hypothesis."))
        if re.search(r"\b(?:json|yaml|toml)\.loads?\s*\(|\bparse\s*\(", stripped):
            if not any("except" in source[i] for i in range(number, min(len(source), number + 5))):
                candidates.append((f"The parser call `{stripped}` at {module_path}:{number} has no nearby exception handling, so malformed input may escape as an opaque failure.", number, f"Feed malformed input to the function containing line {number}; a named boundary error or explicit rejection falsifies the hypothesis."))
        if re.search(r"\b(?:score|verdict|classif\w*)\b.*(?:[<>]=?|==).*\d+\.\d+", stripped):
            candidates.append((f"The decision comparison `{stripped}` at {module_path}:{number} uses a binary float threshold, so rounding at the boundary may flip the result.", number, f"Run inputs immediately below, exactly at, and above the threshold using exact decimal values; stable, documented boundary behavior falsifies the hypothesis."))
        if "math.isclose" in stripped:
            candidates.append((f"The tolerance call `{stripped}` at {module_path}:{number} governs a float decision and must expose an explicit tolerance policy.", number, f"Vary values within and outside the stated tolerance; a documented, stable boundary falsifies this hypothesis."))
        if re.search(r"\b(eval|exec)\s*\(", stripped):
            candidates.append((f"The dynamic evaluation `{stripped}` at {module_path}:{number} may execute data as code instead of treating it as data.", number, f"Supply a payload that would create a harmless sentinel file; absence of the sentinel and explicit rejection falsify the hypothesis."))
    return [Hypothesis(module_path, rank, desc, (line,), test) for rank, (desc, line, test) in enumerate(candidates[:5], 1)]


def generate_hypotheses(triage: TriageManifest) -> HypothesesManifest:
    hypotheses: list[Hypothesis] = []
    audited: list[str] = []
    root = Path(triage.root)
    for module in sorted(triage.modules, key=lambda m: (m.module_class != ModuleClass.CONNECTED_ALIVE, m.path)):
        if module.module_class is not ModuleClass.CONNECTED_ALIVE:
            continue
        path = root / module.path
        source = _lines(path)
        audited.append(module.path)
        hypotheses.extend(_candidates(module.path, source, module.language))
    return HypothesesManifest("1.0", "0.1.0", triage.schema_version, triage.root, int(time.time()), tuple(hypotheses), tuple(audited), ("Hypotheses are unverified candidates; module 3 must perform induction.",))


def write_hypotheses_manifest(manifest: HypothesesManifest, destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
