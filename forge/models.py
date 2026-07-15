"""Strict, serializable models for FORGE module 1."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ModuleClass(str, Enum):
    CONNECTED_ALIVE = "CONNECTED_ALIVE"
    FOSSIL_HIGH_RISK = "FOSSIL_HIGH_RISK"
    DEAD_WEIGHT = "DEAD_WEIGHT"
    FOSSIL_LOW_RISK = "FOSSIL_LOW_RISK"
    DUPLICATE = "DUPLICATE"


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    detail: str


@dataclass(frozen=True)
class ModuleRecord:
    path: str
    language: str
    module_class: ModuleClass
    last_commit_epoch: int | None
    caller_count: int
    import_count: int
    decision_keywords: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class StackFingerprint:
    name: str
    confidence: float
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class TriageManifest:
    schema_version: str
    forge_version: str
    root: str
    generated_at_epoch: int
    stacks: tuple[StackFingerprint, ...]
    modules: tuple[ModuleRecord, ...]
    summary: dict[str, int]
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Hypothesis:
    """A ranked, falsifiable candidate; never a verified finding."""

    module_path: str
    rank: int
    description: str
    file_lines: tuple[int, ...]
    falsification_test: str

    def __post_init__(self) -> None:
        if not self.module_path.strip():
            raise ValueError("module_path is required")
        if self.rank < 1:
            raise ValueError("rank must be positive")
        if not self.description.strip():
            raise ValueError("description is required")
        if not self.file_lines or any(line < 1 for line in self.file_lines):
            raise ValueError("file_lines must contain one or more positive lines")
        if not self.falsification_test.strip():
            raise ValueError("falsification_test is required")


@dataclass(frozen=True)
class HypothesesManifest:
    schema_version: str
    forge_version: str
    triage_schema_version: str
    root: str
    generated_at_epoch: int
    hypotheses: tuple[Hypothesis, ...]
    audited_modules: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
