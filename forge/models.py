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
