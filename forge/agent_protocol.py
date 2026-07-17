"""Mandatory agent protocol: A-D-I plus the complete skills catalog.

The detector implementations are intentionally deterministic, but their
outputs are not allowed to bypass the inquiry protocol.  Static detectors may
stop at ``UNDETERMINED`` when no safe induction harness exists; they must still
record the hypothesis and the falsifying experiment they would run.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from forge.governance.runtime import SkillRun


ADI_STAGES = ("abduction", "deduction", "induction")
AGENT_NAMES = (
    "archaeologist",
    "bug_investigator",
    "integrity_inspector",
    "patch_reviewer",
    "recommendation_agent",
    "report_composer",
    "security_auditor",
    "web_auditor",
)

SKILL_STATUSES = frozenset({"APPLIED", "NOT_APPLICABLE", "UNDETERMINED", "PROCESS_LEVEL", "LOADED_ONLY", "ERROR"})
# These catalogue entries govern how an audit is conducted or reported, not a
# property of one target module.  They deliberately have no fake module-level
# evaluator; a future run-level contract will own them.
PROCESS_LEVEL_SKILLS = frozenset({
    "abductive-engineering", "audit-before-patch", "claim-provenance-discipline",
    "codebase-health-assessment", "daubert-defensible-writing", "diagnosing-bugs",
    "git-discipline", "llm-out-of-the-loop", "red-team-auditing",
    "reverse-engineering", "secure-by-construction", "software-archaeology",
    "surgical-patcher",
})


@dataclass(frozen=True)
class ADIEntry:
    stage: str
    statement: str
    evidence: tuple[str, ...] = ()
    status: str = "UNDETERMINED"

    def __post_init__(self) -> None:
        if self.stage not in ADI_STAGES:
            raise ValueError(f"invalid A-D-I stage: {self.stage}")
        if not self.statement.strip():
            raise ValueError("A-D-I statement is required")


@dataclass(frozen=True)
class SkillApplication:
    name: str
    source: str
    status: str
    evidence: tuple[str, ...]
    limitation: str


@dataclass(frozen=True)
class AgentProtocol:
    agent: str
    adi: tuple[ADIEntry, ...]
    skills: tuple[SkillApplication, ...]
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.agent not in AGENT_NAMES:
            raise ValueError(f"unknown agent: {self.agent}")
        stages = {entry.stage for entry in self.adi}
        missing = set(ADI_STAGES) - stages
        if missing:
            raise ValueError(f"A-D-I ledger missing stages: {sorted(missing)}")

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "adi": [asdict(item) for item in self.adi],
            "skills": [asdict(item) for item in self.skills],
            "scope": list(self.scope),
        }


def skills_catalog(skills_root: str | Path | None = None) -> tuple[tuple[str, str, str], ...]:
    """Load every policy skill, including Markdown-only skills.

    Markdown skills are policy instructions, not executable detectors.  They
    nevertheless belong to the mandatory agent contract and are therefore
    recorded for every agent, with an explicit limitation when no executable
    checker exists yet.
    """
    root = Path(skills_root) if skills_root else Path(__file__).resolve().parents[1] / "skills-gpt"
    records = []
    for path in sorted(root.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^name:\s*(.+?)\s*$", text, re.MULTILINE)
        name = match.group(1).strip() if match else path.stem
        records.append((name, str(path), text))
    return tuple(records)


def mandatory_protocol(
    agent: str,
    observations: Iterable[str],
    scope: Iterable[str],
    skills_root: str | Path | None = None,
    induction_status: str = "UNDETERMINED",
    induction_reason: str = "No language-specific induction harness was registered for this observation.",
    skill_run: SkillRun | None = None,
) -> AgentProtocol:
    """Build the required protocol ledger for every agent invocation."""
    obs = tuple(item for item in observations if item.strip())
    if not obs:
        obs = ("No actionable observation was emitted in the examined scope.",)
    observation_text = "; ".join(obs[:5])
    adi = (
        ADIEntry("abduction", f"Observed evidence may be explained by: {observation_text}.", obs, "PLAUSIBLE_HYPOTHESIS"),
        ADIEntry("deduction", "A falsification experiment must distinguish the observed mechanism from a benign structural explanation.", obs, "PREDICTION_REQUIRED"),
        ADIEntry("induction", induction_reason, obs, induction_status),
    )
    applications = tuple(
        SkillApplication(
            name=name,
            source=source,
            status="PROCESS_LEVEL" if name in PROCESS_LEVEL_SKILLS else "LOADED_ONLY",
            evidence=(
                "This policy governs run-level process and reporting; no module-level contract is claimed."
                if name in PROCESS_LEVEL_SKILLS
                else f"{agent} received the mandatory policy catalog entry {name} before producing its result."
            ,),
            limitation=(
                "Run-level enforcement is an explicit future contract, not a fabricated module scan."
                if name in PROCESS_LEVEL_SKILLS
                else "Policy text is loaded and recorded; semantic enforcement requires an executable checker for this skill."
            ),
        )
        for name, source, _text in skills_catalog(skills_root)
    )
    protocol = AgentProtocol(agent, adi, applications, tuple(scope))
    return apply_skill_run(protocol, skill_run) if skill_run is not None else protocol


def apply_skill_run(protocol: AgentProtocol, skill_run: SkillRun | None) -> AgentProtocol:
    """Project native executable-skill results into one agent's ledger.

    The projection is intentionally evidence-backed: an executable contract is
    APPLIED only when the native runtime classified at least one module in this
    agent's scope as applicable (which is the point at which ``evaluate`` ran).
    """
    if skill_run is None:
        return protocol
    scope = set(protocol.scope)
    executable = set(skill_run.executable_skills)
    findings_by_skill: dict[str, list[str]] = {}
    for finding in skill_run.findings:
        if finding.module_path in scope:
            findings_by_skill.setdefault(finding.agent, []).extend(item.source for item in finding.evidence)
    rewritten: list[SkillApplication] = []
    for item in protocol.skills:
        if item.name in PROCESS_LEVEL_SKILLS:
            rewritten.append(SkillApplication(item.name, item.source, "PROCESS_LEVEL", ("This policy governs run-level process and reporting; no module-level contract is claimed.",), "Run-level enforcement is an explicit future contract, not a fabricated module scan."))
            continue
        if item.name not in executable:
            rewritten.append(item)
            continue
        states = [by_skill.get(item.name) for path, by_skill in skill_run.applicability.items() if path in scope]
        states = [state for state in states if state is not None]
        if "APPLICABLE" in states:
            evidence = tuple(sorted(set(findings_by_skill.get(item.name, ()))))
            if not evidence:
                evidence = (f"Native contract {item.name} evaluated applicable modules with no protocol gap.",)
            rewritten.append(SkillApplication(item.name, item.source, "APPLIED", evidence, "Static contract evidence is structural; aliases and cross-module flow remain limited by the contract."))
        elif "ERROR" in states:
            notes = tuple(note for note in skill_run.limitations if item.name in note) or (f"Native contract {item.name} returned ERROR.",)
            rewritten.append(SkillApplication(item.name, item.source, "ERROR", notes, "The executable checker failed; no application claim is made."))
        elif "UNDETERMINED" in states or not states:
            rewritten.append(SkillApplication(item.name, item.source, "UNDETERMINED", (f"Native contract {item.name} could not establish applicability in this scope.",), "Ambiguous source is not promoted to applicability."))
        else:
            rewritten.append(SkillApplication(item.name, item.source, "NOT_APPLICABLE", (f"Native contract {item.name} was not applicable in this scope.",), "No matching structural signal was found."))
    return AgentProtocol(protocol.agent, protocol.adi, tuple(rewritten), protocol.scope)


def validate_protocols(protocols: dict[str, AgentProtocol]) -> None:
    """Fail closed if any required agent or skill ledger is absent."""
    missing_agents = set(AGENT_NAMES) - set(protocols)
    if missing_agents:
        raise ValueError(f"agent protocol missing: {sorted(missing_agents)}")
    expected_skills = {name for name, _source, _text in skills_catalog()}
    for agent, protocol in protocols.items():
        actual = {item.name for item in protocol.skills}
        missing = expected_skills - actual
        if missing:
            raise ValueError(f"{agent} protocol missing skills: {sorted(missing)}")
        for item in protocol.skills:
            if item.status not in SKILL_STATUSES:
                raise ValueError(f"{agent} protocol has invalid skill status for {item.name}: {item.status}")
            if item.status == "APPLIED" and not tuple(value for value in item.evidence if value.strip()):
                raise ValueError(f"{agent} protocol claims APPLIED for {item.name} without evidence")
