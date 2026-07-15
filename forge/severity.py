"""Deterministic severity and finding-family classification."""
from __future__ import annotations


CORE_MODULE_MARKERS = ("__main__", "runtime", "sealing", "verification", "cronos/chain")


def finding_family(description: str) -> str:
    text = description.lower()
    if "unversioned serialization" in text or "unversioned-serialization" in text:
        return "unversioned-serialization"
    if "parser call" in text or "parser boundary" in text:
        return "parser-boundary"
    if "shell=true" in text:
        return "shell-true"
    if "subprocess" in text or "os.system" in text:
        return "subprocess"
    if "float" in text or "tolerance" in text:
        return "numeric-boundary"
    if "credential" in text or "secret" in text:
        return "credential"
    if "path" in text and "open" in text:
        return "path-traversal"
    if "eval" in text or "exec" in text:
        return "dynamic-evaluation"
    return "other"


def severity_for(module_path: str, epistemic_level: str, description: str, agent: str = "", family: str | None = None) -> str:
    # Agent detectors know the family; use it when supplied instead of
    # guessing from prose.  The fallback preserves compatibility for callers
    # that only have a serialized Finding.
    family = family or finding_family(description)
    score = 2
    if epistemic_level == "CODE FACT":
        score += 1
    elif epistemic_level == "CONFIRMED BY INDUCTION":
        score += 2
    elif epistemic_level == "FALSIFIED":
        score = 0
    if any(marker in module_path for marker in CORE_MODULE_MARKERS):
        score += 1
    if family in {"credential", "path-traversal", "shell-true", "dynamic-evaluation"}:
        score += 2
    if agent == "validate-at-the-boundary":
        score += 1
    if score >= 5:
        return "CRITICAL"
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"
