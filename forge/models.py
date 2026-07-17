"""Strict, serializable models for FORGE module 1."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
from fractions import Fraction


class ModuleClass(str, Enum):
    CONNECTED_ALIVE = "CONNECTED_ALIVE"
    FOSSIL_HIGH_RISK = "FOSSIL_HIGH_RISK"
    DEAD_WEIGHT = "DEAD_WEIGHT"
    FOSSIL_LOW_RISK = "FOSSIL_LOW_RISK"
    DUPLICATE = "DUPLICATE"

class Applicability(str, Enum):
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class ModelRouting:
    """Declarative model assignment for future model-backed runtime stages.

    Built-in FORGE agents currently execute deterministic Python detectors and
    do not invoke an LLM. This shared configuration surface records intended
    routing without pretending that a model was called; configured model names
    are inert metadata until a model-backed adapter is explicitly installed.
    """

    orchestrator: str | None = None
    agents: dict[str, str] = field(default_factory=dict)

    def for_agent(self, agent: str) -> str | None:
        return self.agents.get(agent)

    def to_dict(self) -> dict[str, Any]:
        return {"orchestrator": self.orchestrator, "agents": dict(sorted(self.agents.items()))}


@dataclass(frozen=True)
class Recommendation:
    """A post-audit suggestion, never a finding or an automatic patch."""

    recommendation_id: str
    module_path: str
    action: str
    rationale: str
    regression_risk: str
    basis: tuple[str, ...]
    agent: str = "recommendation_agent"


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    detail: str
    role: str = "primary"

    def __post_init__(self) -> None:
        if self.role not in {"primary", "derived", "recommendation"}:
            raise ValueError("invalid evidence role")

@dataclass(frozen=True)
class ModuleDomainHypothesis:
    """Evidence-backed, non-exclusive hypothesis about one module's domain."""
    module_path: str
    domains: tuple[str, ...]
    confidence: Fraction
    evidence: tuple[Evidence, ...]
    alternatives: tuple[str, ...] = ()

@dataclass(frozen=True)
class SkillContract:
    name: str
    version: str
    obligations: tuple[str, ...]
    checks: tuple[str, ...]
    evidence_required: tuple[str, ...]
    limitations: tuple[str, ...]

@dataclass(frozen=True)
class EvaluationContext:
    root: str
    module: "ModuleRecord"
    source: str
    domain_hypothesis: ModuleDomainHypothesis

@dataclass(frozen=True)
class CoverageReport:
    files_discovered: int
    files_analyzed: int
    eligible_source_files: int
    files_skipped: int
    skipped_reasons: dict[str, tuple[str, ...]]
    ast_verified_families: tuple[str, ...] = ()
    coverage_ratio: Fraction = field(default_factory=lambda: Fraction(0, 1))
    discovery_ratio: Fraction = field(default_factory=lambda: Fraction(0, 1))
    language_coverage: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Fractions keep internal arithmetic exact, but their normalized
        # numerator/denominator lose the audit counts (33/33 becomes 1/1).
        # Coverage is a count claim, so preserve its original denominators.
        data["coverage_ratio"] = {"numerator": self.files_analyzed, "denominator": self.eligible_source_files}
        data["discovery_ratio"] = {"numerator": self.files_analyzed, "denominator": self.files_discovered}
        return data

@dataclass(frozen=True)
class AgentScanResult:
    findings: tuple
    examinations: dict[str, str]
    protocol: Any = None

    def __iter__(self):
        return iter(self.findings)

    def __len__(self):
        return len(self.findings)

    def __eq__(self, other):
        if isinstance(other, (tuple, list)):
            return tuple(self.findings) == tuple(other)
        return super().__eq__(other)


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
    confidence: Fraction
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
    deletion_judgments: dict[str, str] = field(default_factory=dict)
    protocol: Any = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for stack in data.get("stacks", []):
            value = stack.get("confidence")
            if isinstance(value, Fraction):
                stack["confidence"] = {"numerator": value.numerator, "denominator": value.denominator}
        return data


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

# Two legitimate, distinct vocabularies share the epistemic_level field today:
# the red-team-auditing confidence ladder (bug_investigator, security_auditor,
# integrity_inspector) and the skills-runtime protocol-conformance outcomes
# (forge/skills/*, e.g. validate-at-the-boundary). "OBSERVED" is deliberately
# excluded from both: it is the category field's own vocabulary, and reusing
# it as epistemic_level is exactly the conflation bug this validation exists
# to catch (see DECISIONS.md).
RED_TEAM_EPISTEMIC_LEVELS = frozenset({"CODE FACT", "PLAUSIBLE HYPOTHESIS", "CONFIRMED BY INDUCTION", "FALSIFIED"})
PROTOCOL_EPISTEMIC_LEVELS = frozenset({"PROTOCOL_GAP", "DESIGN_INCONSISTENCY", "UNDETERMINED", "NOT_APPLICABLE"})
EPISTEMIC_LEVELS = RED_TEAM_EPISTEMIC_LEVELS | PROTOCOL_EPISTEMIC_LEVELS
CONTROLLABILITY_LEVELS = frozenset({"ATTACKER_CONTROLLED", "INTERNAL_ONLY", "UNDETERMINED"})
EXPLOITABILITY_LEVELS = frozenset({"OBSERVED_BOUNDARY", "PLAUSIBLE", "CONFIRMED", "NOT_ASSESSED"})

@dataclass(frozen=True)
class Finding:
    category: str
    epistemic_level: str
    module_path: str
    description: str
    evidence: tuple[Evidence, ...]
    reasoning: str
    agent: str = "bug_investigator"
    outcome: str = "OBSERVED"
    severity: str = "MEDIUM"
    provenance: tuple[str, ...] = ()
    controllability: str = "UNDETERMINED"
    exploitability: str = "NOT_ASSESSED"
    occurrences: tuple[str, ...] = ()
    def __post_init__(self) -> None:
        if self.category not in {"OBSERVED", "INFERRED", "OPINION"}:
            raise ValueError("invalid finding category")
        if self.epistemic_level not in EPISTEMIC_LEVELS:
            raise ValueError(
                f"invalid epistemic_level {self.epistemic_level!r}; must be one of "
                f"{sorted(EPISTEMIC_LEVELS)} and must not reuse the category field's "
                "own vocabulary (OBSERVED/INFERRED/OPINION)"
            )
        if self.outcome not in {"OBSERVED", "PROTOCOL_GAP", "DESIGN_INCONSISTENCY", "UNDETERMINED", "NOT_APPLICABLE"}:
            raise ValueError("invalid finding outcome")
        if self.severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("invalid finding severity")
        if self.controllability not in CONTROLLABILITY_LEVELS:
            raise ValueError("invalid finding controllability")
        if self.exploitability not in EXPLOITABILITY_LEVELS:
            raise ValueError("invalid finding exploitability")
        if not self.evidence:
            raise ValueError("every finding requires evidence")

@dataclass(frozen=True)
class VerificationManifest:
    schema_version: str
    forge_version: str
    hypotheses_schema_version: str
    root: str
    generated_at_epoch: int
    findings: tuple[Finding, ...]
    discarded: tuple[dict[str, str], ...]
    ast_verified_families: tuple[str, ...] = ()
    ast_unverified_families: tuple[str, ...] = ()
    induction: tuple[dict[str, str], ...] = ()
    repository_snapshot_sha256: str | None = None
    source_attestation: str | None = None
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
