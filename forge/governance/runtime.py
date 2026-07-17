"""Discovery and execution of governance skills without core-specific rules."""
from __future__ import annotations
import importlib.util
import json
import re
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Protocol

from forge.models import Applicability, EvaluationContext, Evidence, Finding, ModuleDomainHypothesis, SkillContract, TriageManifest

class ExecutableSkill(Protocol):
    contract: SkillContract
    def applicability(self, context: EvaluationContext) -> Applicability: ...
    def evaluate(self, context: EvaluationContext) -> tuple[Finding, ...]: ...

@dataclass(frozen=True)
class LoadedSkill:
    contract: SkillContract
    implementation: ExecutableSkill
    source: str

@dataclass(frozen=True)
class SkillRun:
    findings: tuple[Finding, ...]
    hypotheses: tuple[ModuleDomainHypothesis, ...]
    applicability: dict[str, dict[str, str]]
    limitations: tuple[str, ...]
    executable_skills: tuple[str, ...] = ()
    def to_dict(self):
        return {
            "domain_hypotheses": [{"module_path": h.module_path, "domains": h.domains, "confidence": {"numerator": h.confidence.numerator, "denominator": h.confidence.denominator}, "evidence": [e.__dict__ for e in h.evidence], "alternatives": h.alternatives} for h in self.hypotheses],
            "applicability": self.applicability,
            "findings": [f.__dict__ | {"evidence": [e.__dict__ for e in f.evidence]} for f in self.findings],
            "limitations": self.limitations,
            "executable_skills": list(self.executable_skills),
        }

def default_skills_root() -> Path:
    return Path(__file__).resolve().parents[1] / "skills"

def load_skills(skills_root: str | Path | None = None, failures: list[str] | None = None) -> tuple[LoadedSkill, ...]:
    """Discover and load skill plugins under `skills_root`.

    A broken optional plugin must not prevent the core audit from running,
    so it is excluded from the active skill set rather than raising. That
    must not mean it vanishes without a trace, though: pass a `failures`
    list to have each load failure (bad manifest, missing entrypoint,
    manifest/contract mismatch, broken import) appended to it as a
    human-readable note. `run_skills()` passes one through and folds it
    into `SkillRun.limitations`, so a broken plugin is at least visible in
    the audit's own output, not just silently absent from the active set.
    """
    root = Path(skills_root) if skills_root else default_skills_root()
    loaded=[]
    for manifest_path in sorted(root.glob("*/manifest.json")):
        try:
            manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
            module_path=manifest_path.parent / manifest["entrypoint"]
            spec=importlib.util.spec_from_file_location(f"forge_skill_{manifest['name'].replace('-', '_')}", module_path)
            if spec is None or spec.loader is None: raise ValueError(f"cannot load skill entrypoint: {module_path}")
            module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            implementation=getattr(module, manifest["class_name"])()
            if implementation.contract.name != manifest["name"] or implementation.contract.version != manifest["version"]:
                raise ValueError(f"skill manifest/contract mismatch: {manifest_path}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, AttributeError, ImportError) as exc:
            if failures is not None:
                failures.append(f"Skill at {manifest_path} failed to load: {type(exc).__name__}: {exc}")
            continue
        loaded.append(LoadedSkill(implementation.contract, implementation, str(manifest_path)))
    return tuple(loaded)

def infer_domains(triage: TriageManifest) -> tuple[ModuleDomainHypothesis, ...]:
    root=Path(triage.root); out=[]
    for module in triage.modules:
        try: source=(root/module.path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            out.append(ModuleDomainHypothesis(module.path, (), Fraction(0, 1), (), ("unreadable",))); continue
        domains=[]; evidence=[]
        if re.search(r"\b(?:torch|tensorflow|sklearn|numpy|pandas)\b", source):
            domains.append("machine_learning"); evidence.append(Evidence("source_pattern", module.path, "ML framework import or reference"))
        if re.search(r"\b(?:open|json\.loads?|yaml\.loads?|parse)\s*\(", source):
            domains.append("input_boundary"); evidence.append(Evidence("source_pattern", module.path, "input or parser boundary call"))
        if re.search(r"\b(?:hashlib|cryptography|hmac)\b", source):
            domains.append("cryptographic"); evidence.append(Evidence("source_pattern", module.path, "cryptographic library reference"))
        if re.search(r"\b(?:json\.(?:dump|dumps|load|loads)|pickle|sqlite3|\.execute\s*\()", source):
            domains.append("serialization_or_persistence"); evidence.append(Evidence("source_pattern", module.path, "serialization or persistence operation"))
        if re.search(r"\b(?:ledger|audit(?:_log)?|append_only|prev_hash|entry_hash)\b", source, re.IGNORECASE):
            domains.append("audit_or_ledger"); evidence.append(Evidence("source_pattern", module.path, "audit or ledger vocabulary"))
        if re.search(r"\b(?:hashlib|canonical(?:_json|ize)?|seal(?:ed|ing)?|json\.dumps)\b", source, re.IGNORECASE):
            domains.append("determinism_sensitive"); evidence.append(Evidence("source_pattern", module.path, "canonicalization, sealing, or hash operation"))
        unique=tuple(sorted(set(domains)))
        confidence=Fraction(min(len(evidence), 3), 3) if evidence else Fraction(0, 1)
        out.append(ModuleDomainHypothesis(module.path, unique, confidence, tuple(evidence), ("mixed_or_unknown",) if len(unique) != 1 else ()))
    return tuple(out)

def run_skills(triage: TriageManifest, skills_root: str | Path | None = None) -> SkillRun:
    load_failures: list[str] = []
    skills=load_skills(skills_root, failures=load_failures); hypotheses=infer_domains(triage); by_path={h.module_path: h for h in hypotheses}
    findings=[]; applicability={}; limitations=list(load_failures); root=Path(triage.root)
    for module in triage.modules:
        try: source=(root/module.path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            source=""
        context=EvaluationContext(str(root), module, source, by_path[module.path])
        applicability[module.path]={}
        for skill in skills:
            try:
                state=skill.implementation.applicability(context)
                applicability[module.path][skill.contract.name]=state.value
                if state is Applicability.APPLICABLE:
                    findings.extend(skill.implementation.evaluate(context))
            except Exception as exc:
                # A bug or crash in one plugin skill must not take down the
                # whole governance run for every other module and skill.
                applicability[module.path][skill.contract.name]="ERROR"
                limitations.append(f"Skill {skill.contract.name} failed on {module.path}: {exc}")
    return SkillRun(tuple(findings), hypotheses, applicability, tuple(limitations), tuple(skill.contract.name for skill in skills))
