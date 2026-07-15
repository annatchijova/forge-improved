"""Module 2: abductive, read-before-reason hypothesis generation."""
from __future__ import annotations

import json
import time
from pathlib import Path

from forge.models import HypothesesManifest, Hypothesis, ModuleClass, TriageManifest


def _lines(path: Path) -> tuple[str, ...]:
    # Reading the actual source is a hard precondition for generation.
    return tuple(path.read_text(encoding="utf-8", errors="replace").splitlines())


def _candidates(module_path: str, source: tuple[str, ...], language: str) -> list[Hypothesis]:
    joined = "\n".join(source).lower()
    risk_terms = ("input", "parse", "load", "open(", "exec(", "eval(", "subprocess", "socket", "request", "score", "verdict", "validate", "classif")
    if not any(term in joined for term in risk_terms):
        return []
    lines = tuple(i for i, line in enumerate(source, 1) if any(term in line.lower() for term in risk_terms)) or (1,)
    first = lines[0]
    raw = [
        ("If an untrusted input reaches this module without complete boundary validation, a crafted value could trigger an exception or alter the result.", f"Run the module's public entry point with malformed, empty, and non-finite inputs; if each is rejected with a named boundary error and no result changes, falsify this hypothesis."),
        ("If parsing or loading accepts a shape different from the downstream contract, a minimally malformed fixture could produce silent corruption rather than a clear failure.", f"Execute a fixture with one missing, extra, or wrong-typed field and compare the returned value; a deterministic, explicit rejection falsifies this hypothesis."),
        ("If an external resource or subprocess failure is swallowed, the caller could receive a plausible result that is marked as successful despite missing work.", f"Force the dependency to fail (invalid path, unavailable command, or injected exception); an observable failure or explicit degraded status falsifies this hypothesis."),
        ("If repeated execution is not deterministic for identical source state and input, the same audit could emit different outputs and weaken reproducibility.", f"Run the same entry point twice in isolated processes with identical bytes and environment; byte-identical outputs falsify this hypothesis."),
        ("If this live module participates in a decision path without a regression seam, a boundary case may change the decision without a focused executable check.", f"Run the smallest available integration entry point at each exact threshold and record the result; complete boundary coverage with a passing regression test falsifies this hypothesis."),
    ]
    return [Hypothesis(module_path, i, desc, (first,), test) for i, (desc, test) in enumerate(raw[:5], 1)]


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
