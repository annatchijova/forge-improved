"""The single FORGE execution engine.

Frontends may parse arguments or expose tools, but repository auditing and
governance execution live here. The engine is deliberately UI-agnostic.
"""
from __future__ import annotations
import ast
import json
import resource
import shutil
import tempfile
import time
from collections import Counter
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable

from forge.agents import archaeologist, bug_investigator, integrity_inspector, report_composer, security_auditor, web_auditor
from forge.detector.stack import discover_files, is_excluded_by_policy, write_manifest
from forge.evidence_package import build_repository_profile, write_markdown_report, write_repository_profile
from forge.governance.runtime import infer_domains, load_skills, run_skills
from forge.hypotheses import generate_hypotheses, write_hypotheses_manifest
from forge.io import load_json
from forge.severity import finding_family, severity_for
from forge.sharding import deterministic_shards, validate_shards
from forge.models import AgentScanResult, CoverageReport, Evidence, Finding, ModelRouting, TriageManifest, VerificationManifest
from forge.metrics import collect_metrics
from forge.contradictions import find_contradictions
from forge.snapshot import snapshot_sha256
from forge.report import render_report
from forge.reporting import render_dashboard
from forge.sealing import read_and_verify, write_sealed_manifest, write_findings_jsonl
from forge.tracing import RuntimeTrace
from forge.verification import verify_hypotheses, write_verification_manifest
from forge.git_refs import archive_ref, changed_files, resolve_ref
from forge.attestation import attest_manifest, verify_manifest_attestation
from forge.agent_protocol import mandatory_protocol, validate_protocols


def _peak_rss_bytes() -> int | None:
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if __import__("sys").platform == "darwin" else value * 1024)
    except (AttributeError, OSError, ValueError):
        return None

def _coverage(root: Path, families=(), discovered=None, analyzed_paths=()) -> CoverageReport:
    discovered = discovered if discovered is not None else discover_files(root, include_excluded=True)
    skipped: dict[str, list[str]] = {"excluded_by_policy": [], "syntax_error": [], "binary_or_unreadable": [], "non_python_not_analyzed": []}
    analyzed = 0
    language_coverage: dict[str, dict[str, int]] = {}
    language_names = {".py": "Python", ".js": "JavaScript/TypeScript", ".jsx": "JavaScript/TypeScript", ".ts": "JavaScript/TypeScript", ".tsx": "JavaScript/TypeScript"}
    def account(path: Path, state: str) -> None:
        language = language_names.get(path.suffix.lower(), path.suffix.lower().lstrip(".").upper() or "Other")
        language_coverage.setdefault(language, {"analyzed": 0, "abstained": 0})[state] += 1
    analyzed_paths = set(analyzed_paths)
    for path in discovered:
        rel = str(path.relative_to(root))
        if is_excluded_by_policy(path, root): skipped["excluded_by_policy"].append(rel); continue
        try: source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError): skipped["binary_or_unreadable"].append(rel); account(path, "abstained"); continue
        if rel in analyzed_paths:
            analyzed += 1; account(path, "analyzed")
            continue
        if path.suffix != ".py": skipped["non_python_not_analyzed"].append(rel); account(path, "abstained"); continue
        try: ast.parse(source)
        except SyntaxError: skipped["syntax_error"].append(rel); account(path, "abstained"); continue
        analyzed += 1; account(path, "analyzed")
    compact = {key: tuple(sorted(value)) for key, value in skipped.items() if value}
    return CoverageReport(len(discovered), analyzed, sum(map(len, compact.values())), compact, tuple(families), Fraction(analyzed, len(discovered) or 1), dict(sorted(language_coverage.items())))

def _agent_finding(agent: str, item) -> Finding:
    detail = item.description
    outcome = "PROTOCOL_GAP" if agent == "validate-at-the-boundary" else "OBSERVED"
    return Finding(
        "OBSERVED", "CODE FACT", item.path, detail,
        (Evidence("source", f"{item.path}:{item.line}", detail, "primary"),),
        f"AST detector emitted this observation: {item.family}.", agent, outcome,
        provenance=("AST",),
        controllability=getattr(item, "controllability", "UNDETERMINED"),
        exploitability=getattr(item, "exploitability", "NOT_ASSESSED"),
    )


def _with_severity(finding: Finding, family: str | None = None) -> Finding:
    return Finding(finding.category, finding.epistemic_level, finding.module_path,
                   finding.description, finding.evidence, finding.reasoning,
                   finding.agent, finding.outcome,
                   severity_for(
                       finding.module_path, finding.epistemic_level, finding.description, finding.agent,
                       family=family, controllability=finding.controllability,
                       exploitability=finding.exploitability,
                   ),
                   finding.provenance, finding.controllability, finding.exploitability, finding.occurrences)


def _finding_identity(finding: Finding) -> tuple[str, str, int, tuple[tuple[str, str, str], ...]]:
    """Build the stable identity used to merge genuinely duplicate findings."""
    line = 0
    for item in finding.evidence:
        match = __import__("re").search(r":(\d+)(?::\d+)?$", item.source)
        if match:
            line = int(match.group(1))
            break
    def normalized_evidence(detail: str) -> str:
        # Variable names in a one-argument code expression do not change the
        # risk identity (`json.dumps(payload)` vs `json.dumps(report)`). Keep
        # all other prose untouched so distinct evidence is never erased.
        compact = " ".join(detail.split())
        return __import__("re").sub(r"(?<=\()\s*[A-Za-z_]\w*(?=\s*[,\)])", "_", compact)
    evidence = tuple(sorted((item.kind, item.source, normalized_evidence(item.detail)) for item in finding.evidence))
    return finding_family(finding.description), finding.module_path, line, evidence


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse normalized risk identities while retaining every occurrence."""
    merged: dict[tuple[str, str, int, tuple[tuple[str, str, str], ...]], Finding] = {}
    agents: dict[tuple[str, str, int, tuple[tuple[str, str, str], ...]], set[str]] = {}
    occurrences: dict[tuple[str, str, int, tuple[tuple[str, str, str], ...]], list[str]] = {}
    for finding in findings:
        identity = _finding_identity(finding)
        if identity not in merged:
            merged[identity] = finding
            agents[identity] = {finding.agent}
            occurrences[identity] = list(finding.occurrences) or [item.source for item in finding.evidence]
        else:
            agents[identity].add(finding.agent)
            occurrences[identity].extend(finding.occurrences or tuple(item.source for item in finding.evidence))
    result: list[Finding] = []
    for identity, finding in merged.items():
        provenance = list(finding.provenance)
        if len(agents[identity]) > 1:
            provenance.append("MULTIPLE_AGENTS")
        result.append(replace(finding, provenance=tuple(dict.fromkeys(provenance)), occurrences=tuple(occurrences[identity])))
    return result


def _attach_provenance(findings: list[Finding]) -> list[Finding]:
    agents_by_module: dict[str, set[str]] = {}
    for finding in findings:
        agents_by_module.setdefault(finding.module_path, set()).add(finding.agent)
    enriched = []
    for finding in findings:
        provenance = list(finding.provenance)
        if any(item.kind == "source" for item in finding.evidence):
            provenance.append("AST")
        if finding.epistemic_level == "CONFIRMED BY INDUCTION":
            provenance.append("REPRODUCED")
        else:
            provenance.append("RUNTIME_NOT_EXECUTED")
        if len(agents_by_module.get(finding.module_path, set())) > 1:
            provenance.append("MULTIPLE_AGENTS")
        enriched.append(replace(finding, provenance=tuple(dict.fromkeys(provenance))))
    return enriched

@dataclass(frozen=True)
class AuditResult:
    repo: str
    connected_alive: int
    findings: int
    discarded: int
    finding_records: tuple[Finding, ...]
    coverage: dict[str, Any]
    artifacts: dict[str, str]
    status: str = "COMPLETE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "connected_alive": self.connected_alive,
            "findings": self.findings,
            "discarded": self.discarded,
            "finding_records": [asdict(item) for item in self.finding_records],
            "coverage": self.coverage,
            "artifacts": self.artifacts,
            "status": self.status,
        }

class Runtime:
    """Reusable, stateless-per-run FORGE execution engine."""
    def __init__(self, skills_root: str | Path | None = None, max_connected: int = 100,
                 triage_override: Callable | None = None,
                 model_routing: ModelRouting | None = None,
                 cronos_db: str | Path | None = None,
                 induction: bool = True):
        """Create a runtime.

        By default triage uses Archaeologist's enriched path, including
        deletion judgments. ``triage_override`` is an explicit escape hatch
        for callers that need a supplied triage function (for example,
        compatibility tests); when set, that callable is used exactly and
        deletion judgments are not added by this runtime.
        """
        self.skills_root = skills_root
        self.max_connected = max_connected
        self._triage_override = triage_override
        self.model_routing = model_routing or ModelRouting()
        self.cronos_db = Path(cronos_db) if cronos_db is not None else None
        self.induction = induction

    @staticmethod
    def _event(trace: RuntimeTrace, cronos, kind: str, **payload: Any) -> None:
        trace.record(kind, **payload)
        if cronos is None:
            return
        summary = json.dumps(payload, sort_keys=True, default=str)
        cronos.call_tool(f"forge.{kind}", summary[:4000])
        if kind == "finding_emitted":
            cronos.add_evidence(payload.get("description", "finding emitted"))
        elif kind == "hypotheses_discarded":
            for record in payload.get("records", ()):
                cronos.discard_hypothesis(record.get("module_path", "unknown"), record.get("reason", "discarded"))

    def _phase_start(self, trace: RuntimeTrace, cronos, phase: str) -> float:
        started = time.monotonic()
        self._event(trace, cronos, "phase_started", phase=phase, peak_rss_bytes=_peak_rss_bytes())
        return started

    def _phase_end(self, trace: RuntimeTrace, cronos, phase: str, started: float) -> None:
        self._event(
            trace, cronos, "phase_completed", phase=phase,
            elapsed_seconds=str(round(time.monotonic() - started, 6)),
            peak_rss_bytes=_peak_rss_bytes(),
        )

    def triage_repository(self, repo: str | Path) -> TriageManifest:
        return self._triage_override(repo) if self._triage_override is not None else archaeologist.assess(repo)

    def infer_module_domains(self, repo: str | Path):
        return infer_domains(self.triage_repository(repo))

    def list_available_skills(self) -> tuple[dict[str, Any], ...]:
        return tuple({"name": skill.contract.name, "version": skill.contract.version, "contract": asdict(skill.contract), "source": skill.source} for skill in load_skills(self.skills_root))

    def run_skill(self, repo: str | Path, skill_name: str | None = None):
        triage_manifest = self.triage_repository(repo)
        result = run_skills(triage_manifest, self.skills_root)
        if skill_name is None: return result
        known = {item["name"] for item in self.list_available_skills()}
        if skill_name not in known: raise ValueError(f"unknown skill: {skill_name}")
        return type(result)(tuple(f for f in result.findings if f.agent == skill_name), result.hypotheses, {path: {skill_name: states.get(skill_name, "NOT_APPLICABLE")} for path, states in result.applicability.items()}, result.limitations, (skill_name,))

    def audit(self, repo: str | Path, output_dir: str | Path, max_connected: int | None = None,
              ref_context: dict[str, Any] | None = None) -> AuditResult:
        trace = RuntimeTrace()
        cronos_context = nullcontext(None)
        store = None
        if self.cronos_db is not None:
            root = Path(repo).resolve()
            database = self.cronos_db.expanduser().resolve()
            if database == root or root in database.parents:
                raise ValueError("cronos_db must be outside the audited repository")
            from forge.cronos import CronosTracer, TraceStore
            store = TraceStore(str(database))
            cronos_context = CronosTracer(store, "forge-runtime", "", "", objective=f"Audit repository {Path(repo).resolve()}")
        with cronos_context as cronos:
            try:
                return self._audit(repo, output_dir, max_connected, trace, cronos, ref_context)
            except Exception as exc:
                self._event(trace, cronos, "run_failed", exception_type=type(exc).__name__, message=str(exc))
                try:
                    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
                    (out / "audit-trace.json").write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True) + "\n")
                except OSError:
                    pass
                raise

    def _audit(self, repo: str | Path, output_dir: str | Path, max_connected: int | None, trace: RuntimeTrace, cronos=None,
               ref_context: dict[str, Any] | None = None) -> AuditResult:
        root, out = Path(repo).resolve(), Path(output_dir)
        started = time.monotonic(); self._event(trace, cronos, "run_started", repository=str(root), max_connected=self.max_connected if max_connected is None else max_connected, model_routing=self.model_routing.to_dict())
        discovery_started = self._phase_start(trace, cronos, "discovery")
        discovered = discover_files(root, include_excluded=True)
        repository_snapshot_sha256 = snapshot_sha256(root, discovered)
        out.mkdir(parents=True, exist_ok=True)
        self._phase_end(trace, cronos, "discovery", discovery_started)
        if ref_context is not None:
            self._event(trace, cronos, "ref_resolved", **ref_context)
        triage_started = self._phase_start(trace, cronos, "triage")
        triage_manifest = self.triage_repository(root)
        self._event(trace, cronos, "repository_discovered", modules=len(triage_manifest.modules), stacks=[item.name for item in triage_manifest.stacks])
        self._event(trace, cronos, "modules_classified", summary=triage_manifest.summary, deletion_judgments=triage_manifest.deletion_judgments)
        self._phase_end(trace, cronos, "triage", triage_started)
        connected = triage_manifest.summary.get("CONNECTED_ALIVE", 0)
        limit = self.max_connected if max_connected is None else max_connected
        if limit < 1:
            raise ValueError(f"scope guard: max_connected must be positive, got {limit}")
        if connected > limit:
            connected_paths = [item.path for item in triage_manifest.modules if item.module_class.value == "CONNECTED_ALIVE"]
            if len(connected_paths) != connected:
                raise ValueError(f"scope guard: triage manifest declares {connected} CONNECTED_ALIVE modules but does not provide matching module paths")
            return self._audit_sharded(root, out, triage_manifest, limit, trace, cronos)
        web_degraded: list[str] = []
        web_started = self._phase_start(trace, cronos, "web_auditor")
        try:
            connected_paths = {module.path for module in triage_manifest.modules if module.module_class.value == "CONNECTED_ALIVE"}
            web_result, web_analyzed_paths = web_auditor.audit(root, connected_paths)
        except Exception as exc:
            message = f"web_auditor unavailable: {type(exc).__name__}: {exc}"
            web_degraded.append(message)
            web_result, web_analyzed_paths = AgentScanResult((), {}, mandatory_protocol("web_auditor", (message,), ())), ()
            self._event(trace, cronos, "agent_degraded", agent="web_auditor", error=message)
        self._event(trace, cronos, "agent_completed", agent="web_auditor", findings=len(web_result.findings), examinations=web_result.examinations)
        self._phase_end(trace, cronos, "web_auditor", web_started)
        coverage_started = self._phase_start(trace, cronos, "coverage")
        coverage = _coverage(root, discovered=discovered, analyzed_paths=web_analyzed_paths)
        self._event(trace, cronos, "coverage_collected", discovered=coverage.files_discovered, analyzed=coverage.files_analyzed, skipped=coverage.files_skipped, skipped_reasons=coverage.skipped_reasons)
        self._phase_end(trace, cronos, "coverage", coverage_started)
        governance_started = self._phase_start(trace, cronos, "governance")
        governance = run_skills(triage_manifest, self.skills_root)
        self._event(trace, cronos, "domain_hypotheses_formed", hypotheses=governance.to_dict()["domain_hypotheses"])
        self._event(trace, cronos, "skill_applicability_evaluated", applicability=governance.applicability)
        self._event(trace, cronos, "skill_contracts_executed", findings=len(governance.findings), limitations=governance.limitations)
        self._phase_end(trace, cronos, "governance", governance_started)
        bug_started = self._phase_start(trace, cronos, "bug_investigator")
        bug = bug_investigator.investigate(triage_manifest, induce=self.induction)
        self._event(trace, cronos, "hypotheses_generated", count=len(bug.hypotheses), modules=list(bug.manifest.audited_modules))
        self._event(trace, cronos, "hypotheses_verified", discarded=len(bug.verification.discarded), findings=len(bug.verification.findings))
        self._phase_end(trace, cronos, "bug_investigator", bug_started)
        degraded_reasons: list[str] = list(web_degraded)
        static_started = self._phase_start(trace, cronos, "static_agents")
        try:
            connected_paths = {module.path for module in triage_manifest.modules if module.module_class.value == "CONNECTED_ALIVE"}
            security_result = security_auditor.audit(root, connected_paths)
        except Exception as exc:
            message = f"security_auditor unavailable: {type(exc).__name__}: {exc}"
            degraded_reasons.append(message)
            security_result = AgentScanResult((), {"*": "agent_unavailable"}, mandatory_protocol("security_auditor", (message,), ()))
            self._event(trace, cronos, "agent_degraded", agent="security_auditor", error=message)
        try:
            ml_domain_paths = frozenset(h.module_path for h in governance.hypotheses if "machine_learning" in h.domains)
            integrity_result = integrity_inspector.inspect(root, connected_paths, ml_domain_paths=ml_domain_paths)
        except Exception as exc:
            message = f"integrity_inspector unavailable: {type(exc).__name__}: {exc}"
            degraded_reasons.append(message)
            integrity_result = AgentScanResult((), {"*": "agent_unavailable"}, mandatory_protocol("integrity_inspector", (message,), ()))
            self._event(trace, cronos, "agent_degraded", agent="integrity_inspector", error=message)
        self._event(trace, cronos, "agent_completed", agent="security_auditor", findings=len(security_result.findings), examinations=security_result.examinations)
        self._event(trace, cronos, "agent_completed", agent="integrity_inspector", findings=len(integrity_result.findings), examinations=integrity_result.examinations)
        self._phase_end(trace, cronos, "static_agents", static_started)
        canonical_started = self._phase_start(trace, cronos, "canonicalization")
        findings = [_with_severity(Finding(f.category, f.epistemic_level, f.module_path, f.description, f.evidence, f.reasoning, "bug_investigator", f.outcome)) for f in bug.verification.findings]
        findings += [_with_severity(_agent_finding("security_auditor", item), family=item.family) for item in security_result.findings]
        findings += [_with_severity(_agent_finding("integrity_inspector", item), family=item.family) for item in integrity_result.findings]
        findings += [_with_severity(_agent_finding("web_auditor", item), family=item.family) for item in web_result.findings]
        findings += [_with_severity(item) for item in governance.findings]
        findings = _attach_provenance(_deduplicate_findings(findings))
        from forge.agents import patch_reviewer, recommendation_agent, report_composer
        from forge.agent_protocol import apply_skill_run
        protocols = {
            "archaeologist": triage_manifest.protocol or mandatory_protocol(
                "archaeologist",
                (f"classified {len(triage_manifest.modules)} modules and recorded triage evidence",),
                (module.path for module in triage_manifest.modules),
            ),
            "bug_investigator": bug.protocol,
            "security_auditor": security_result.protocol,
            "integrity_inspector": integrity_result.protocol,
            "web_auditor": web_result.protocol,
            "patch_reviewer": patch_reviewer.protocol(),
            "recommendation_agent": recommendation_agent.protocol(),
            "report_composer": report_composer.protocol(),
        }
        protocols = {agent: apply_skill_run(protocol, governance) for agent, protocol in protocols.items()}
        validate_protocols(protocols)
        self._event(
            trace, cronos, "agent_protocols_validated",
            agents=sorted(protocols),
            skills=sorted({skill.name for protocol in protocols.values() for skill in protocol.skills}),
            adi_stages=["abduction", "deduction", "induction"],
        )
        contradictions = find_contradictions(findings, bug.verification.discarded)
        if contradictions:
            self._event(trace, cronos, "contradictions_detected", contradictions=[item.to_dict() for item in contradictions])
        for finding in findings:
            self._event(trace, cronos, "finding_emitted", agent=finding.agent, module_path=finding.module_path, category=finding.category, outcome=finding.outcome, description=finding.description, evidence=[asdict(item) for item in finding.evidence])
        self._event(trace, cronos, "hypotheses_discarded", count=len(bug.verification.discarded), records=bug.verification.discarded)
        self._phase_end(trace, cronos, "canonicalization", canonical_started)
        verification = VerificationManifest("2.0", "0.1.0", bug.verification.hypotheses_schema_version, str(root), int(time.time()), tuple(findings), bug.verification.discarded, bug.verification.ast_verified_families, bug.verification.ast_unverified_families, bug.verification.induction, repository_snapshot_sha256)
        verification = replace(verification, source_attestation=attest_manifest(verification.to_dict()))
        coverage = CoverageReport(coverage.files_discovered, coverage.files_analyzed, coverage.files_skipped, coverage.skipped_reasons, verification.ast_verified_families, coverage.coverage_ratio, coverage.language_coverage)
        triage_path, hypotheses_path = out / "triage-manifest.json", out / "hypotheses-manifest.json"
        verification_path, sealed_path, coverage_path = out / "verification-manifest.json", out / "verification-manifest.sealed.json", out / "coverage-report.json"
        skills_path, metrics_path, report_path = out / "skills-runtime.json", out / "metrics.json", out / "forge-report.html"
        profile_path, markdown_path, report_json_path = out / "repository-profile.json", out / "report.md", out / "report.json"
        write_manifest(triage_manifest, triage_path); write_hypotheses_manifest(bug.manifest, hypotheses_path)
        write_verification_manifest(verification, verification_path)
        coverage_path.write_text(json.dumps(coverage.to_dict(), indent=2, sort_keys=True) + "\n")
        skills_path.write_text(json.dumps(governance.to_dict(), indent=2, sort_keys=True) + "\n")
        bug_generated_paths = {h.module_path for h in bug.manifest.hypotheses}; bug_finding_paths = {f.module_path for f in findings if f.agent == "bug_investigator"}
        def bug_status(module):
            if module.module_class.value != "CONNECTED_ALIVE": return "excluded_by_scope"
            if module.path in bug_finding_paths: return "examined_with_findings"
            if module.path in bug_generated_paths: return "hypothesis_discarded_benign"
            return "no_hypothesis_generated"
        agent_metrics = {
            "archaeologist": {"modules_classified": len(triage_manifest.modules), "elapsed_seconds": str(round(time.monotonic() - started, 6))},
            "bug_investigator": {"hypotheses_generated": len(bug.hypotheses), "discarded": len(verification.discarded), "survived": len([f for f in findings if f.agent == "bug_investigator"]), "examinations": {m.path: bug_status(m) for m in triage_manifest.modules}},
            "security_auditor": {"findings_per_family": {family: sum(item.family == family for item in security_result.findings) for family in ("hardcoded-credential", "unsafe-deserialization", "path-traversal", "unverified-webhook")}, "examinations": security_result.examinations},
            "integrity_inspector": {"findings_per_family": {family: sum(item.family == family for item in integrity_result.findings) for family in ("decision-adjacent-float", "money-as-float", "unversioned-serialization")}, "examinations": integrity_result.examinations},
            "web_auditor": {"findings_per_family": {family: sum(item.family == family for item in web_result.findings) for family in ("dynamic-evaluation", "subprocess", "parser-boundary", "path-traversal")}, "examinations": web_result.examinations},
            "governance_skills": {"loaded": [item["name"] for item in self.list_available_skills()], "findings": len(governance.findings), "applicability_counts": {state: sum(state in values.values() for values in governance.applicability.values()) for state in ("APPLICABLE", "NOT_APPLICABLE", "UNDETERMINED")}},
        }
        metrics = collect_metrics(root=root, discovered=discovered, triage=triage_manifest, coverage=coverage, governance=governance, findings=findings, discarded=verification.discarded, trace=trace, skills=self.list_available_skills(), hypothesis_limitations=bug.manifest.limitations, degraded_reasons=degraded_reasons, contradiction_records=contradictions, repository_snapshot_sha256=repository_snapshot_sha256)
        metrics["agent_metrics"] = agent_metrics
        metrics["agent_protocols"] = {name: protocol.to_dict() for name, protocol in protocols.items()}
        metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
        profile = build_repository_profile(root=str(root), triage=triage_manifest, governance=governance, coverage=coverage, metrics=metrics, findings=findings, elapsed_seconds=time.monotonic() - started)
        write_repository_profile(profile, profile_path)
        self._event(trace, cronos, "metrics_computed", metrics=metrics)
        for name, path in (("triage", triage_path), ("hypotheses", hypotheses_path), ("verification", verification_path), ("coverage", coverage_path), ("skills", skills_path), ("metrics", metrics_path), ("profile", profile_path)):
            self._event(trace, cronos, "artifact_written", artifact=name, path=str(path))
        self._event(trace, cronos, "artifact_written", artifact="report", path=str(report_path))
        self._event(trace, cronos, "seal_created", artifact="sealed", findings=len(findings))
        # A provisional seal gives the post-audit agents a verified input.  It
        # is replaced below after every agent/event has completed.
        write_sealed_manifest(verification, sealed_path, trace.to_dict())
        rendered_reports = render_dashboard(out)
        recommendations = recommendation_agent.recommend(sealed_path, metrics_path)
        recommendations_path = out / "recommendations.json"
        recommendations_path.write_text(json.dumps([item.__dict__ for item in recommendations], indent=2, sort_keys=True, default=str) + "\n")
        self._event(trace, cronos, "artifact_written", artifact="recommendations", path=str(recommendations_path), count=len(recommendations))
        report_composer.compose(triage_path, hypotheses_path, sealed_path, report_path, coverage_path, metrics)
        self._event(trace, cronos, "agent_completed", agent="report_composer", adi_stages=["abduction", "deduction", "induction"])
        sealed_payload = load_json(sealed_path, f"sealed manifest {sealed_path}")
        write_markdown_report(sealed=sealed_payload, metrics=metrics, profile=profile, destination=markdown_path)
        report_json_path.write_text(json.dumps({
            "schema_version": "1.0",
            "finding_set_digest": sealed_payload.get("manifest", {}).get("finding_set_digest"),
            "records": [entry.get("finding", {}) for entry in sealed_payload.get("chain", [])],
            "status": "VERIFIED",
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        findings_jsonl_path = out / "findings.jsonl"
        # Per-finding hashes exclude audit_trace_hash (see seal_findings), so
        # this is stable whether written from the provisional or final seal.
        write_findings_jsonl(load_json(sealed_path, f"sealed manifest {sealed_path}"), findings_jsonl_path)
        self._event(trace, cronos, "artifact_written", artifact="findings_jsonl", path=str(findings_jsonl_path))
        self._event(trace, cronos, "run_completed", findings=len(findings), elapsed_seconds=str(round(time.monotonic() - started, 6)))
        trace_path = out / "audit-trace.json"
        trace_path.write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True) + "\n")
        write_sealed_manifest(verification, sealed_path, trace.to_dict())
        artifacts = {"triage": str(triage_path), "hypotheses": str(hypotheses_path), "verification": str(verification_path), "sealed": str(sealed_path), "coverage": str(coverage_path), "skills": str(skills_path), "metrics": str(metrics_path), "profile": str(profile_path), "report": str(report_path), "markdown": str(markdown_path), "trace": str(trace_path), "recommendations": str(recommendations_path), "findings_jsonl": str(findings_jsonl_path), **{key: value for key, value in rendered_reports.items() if key != "report"}, "report_json": str(report_json_path)}
        if self.cronos_db is not None:
            artifacts["cronos_db"] = str(self.cronos_db)
        return AuditResult(str(root), connected, len(findings), len(verification.discarded), tuple(findings), coverage.to_dict(), artifacts)

    def _audit_sharded(self, root: Path, out: Path, triage_manifest: TriageManifest,
                       max_connected: int, trace: RuntimeTrace, cronos=None) -> AuditResult:
        """Run bounded sequential shard audits without fabricating a parent seal."""
        connected_paths = [item.path for item in triage_manifest.modules if item.module_class.value == "CONNECTED_ALIVE"]
        shards = deterministic_shards(connected_paths, max_connected)
        validate_shards(shards, connected_paths, max_connected)
        self._event(trace, cronos, "sharding_required", connected_modules=len(connected_paths), shard_count=len(shards), max_connected=max_connected)
        shard_root = out / "shards"
        records: list[dict[str, Any]] = []
        findings: list[Finding] = []
        discarded = 0
        statuses: list[str] = []
        discovered = discover_files(root, include_excluded=True)
        for index, shard in enumerate(shards, 1):
            shard_started = self._phase_start(trace, cronos, f"shard_{index:04d}")
            selected = tuple(
                item for item in triage_manifest.modules
                if item.module_class.value != "CONNECTED_ALIVE" or item.path in shard
            )
            summary = dict(Counter(item.module_class.value for item in selected))
            shard_manifest = replace(
                triage_manifest,
                modules=selected,
                summary=summary,
                limitations=tuple(triage_manifest.limitations) + (
                    f"This is shard {index}/{len(shards)} of a deterministic {len(shards)}-shard audit; only its CONNECTED_ALIVE paths are in scope.",
                ),
            )
            shard_output = shard_root / f"shard-{index:04d}"
            shard_runtime = Runtime(
                skills_root=self.skills_root,
                max_connected=max_connected,
                triage_override=lambda _repo, manifest=shard_manifest: manifest,
                model_routing=self.model_routing,
                induction=self.induction,
            )
            try:
                result = shard_runtime.audit(root, shard_output, max_connected=max_connected)
                findings.extend(result.finding_records)
                discarded += result.discarded
                statuses.append(result.status)
                records.append({
                    "index": index,
                    "paths": list(shard),
                    "status": result.status,
                    "findings": result.findings,
                    "discarded": result.discarded,
                    "artifacts": result.artifacts,
                })
            except Exception as exc:
                statuses.append("BLOCKED")
                records.append({"index": index, "paths": list(shard), "status": "BLOCKED", "error": f"{type(exc).__name__}: {exc}"})
            self._phase_end(trace, cronos, f"shard_{index:04d}", shard_started)
        status = "PARTIAL_SHARDED" if records and all(item.get("status") == "COMPLETE" for item in records) else "BLOCKED"
        plan = {
            "sharding_schema_version": "1.0",
            "status": status,
            "repository": str(root),
            "max_connected": max_connected,
            "connected_modules": len(connected_paths),
            "shards": records,
            "parent_seal": "NOT_GENERATED; each completed shard has an independent seal",
        }
        plan_path = out / "shards.json"
        out.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        analyzed = sum(item.get("coverage", {}).get("files_analyzed", 0) for item in records if item.get("status") == "COMPLETE")
        coverage = {
            "sharded": True,
            "files_discovered": len(discovered),
            "files_analyzed": analyzed,
            "files_skipped": max(0, len(discovered) - analyzed),
            "coverage_ratio": {"numerator": analyzed, "denominator": len(discovered) or 1},
            "shard_count": len(shards),
        }
        artifacts = {"shards": str(plan_path)}
        return AuditResult(str(root), len(connected_paths), len(findings), discarded, tuple(findings), coverage, artifacts, status)

    def audit_ref(self, repo: str | Path, ref: str, output_dir: str | Path,
                  max_connected: int | None = None, keep_checkout: bool = False) -> AuditResult:
        """Audit a committed Git ref in an isolated archive, never changing repo state."""
        repository = Path(repo).resolve()
        if not repository.is_dir():
            raise ValueError(f"repository path is not a directory: {repo}")
        commit = resolve_ref(repository, ref)
        temporary = Path(tempfile.mkdtemp(prefix="forge-ref-"))
        try:
            archive_ref(repository, commit, temporary)
            result = self.audit(
                temporary,
                output_dir,
                max_connected=max_connected,
                ref_context={"ref": ref, "commit": commit},
            )
            if keep_checkout:
                return result
            return result
        finally:
            if not keep_checkout:
                shutil.rmtree(temporary, ignore_errors=True)

    def compare_refs(self, repo: str | Path, base_ref: str, head_ref: str,
                     output_dir: str | Path, max_connected: int | None = None) -> dict[str, Any]:
        """Audit two committed refs and emit the governance delta between them."""
        repository = Path(repo).resolve()
        base_commit = resolve_ref(repository, base_ref)
        head_commit = resolve_ref(repository, head_ref)
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        base_result = self.audit_ref(repository, base_ref, destination / "base", max_connected=max_connected)
        head_result = self.audit_ref(repository, head_ref, destination / "head", max_connected=max_connected)
        from forge.comparison import compare_runs
        comparison = compare_runs(destination / "base", destination / "head")
        comparison.update({
            "comparison_kind": "git_refs",
            "repository": str(repository),
            "base_ref": base_ref,
            "base_commit": base_commit,
            "head_ref": head_ref,
            "head_commit": head_commit,
            "changed_files": list(changed_files(repository, base_ref, head_ref)),
            "base_run": base_result.artifacts,
            "head_run": head_result.artifacts,
        })
        comparison_path = destination / "branch-comparison.json"
        comparison_path.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        comparison["comparison_artifact"] = str(comparison_path)
        return comparison

    def verify_findings(self, sealed_path: str | Path) -> dict[str, Any]:
        return read_and_verify(sealed_path)

    def get_findings(self, run_output_dir: str | Path, agent: str | None = None) -> list[dict[str, Any]]:
        data = load_json(Path(run_output_dir) / "verification-manifest.sealed.json", f"sealed manifest in {run_output_dir}")
        findings = [entry.get("finding", {}) for entry in data.get("chain", [])]
        return [item for item in findings if agent is None or item.get("agent", "bug_investigator") == agent]

    def get_audit_trace(self, run_output_dir: str | Path) -> dict[str, Any]:
        path = Path(run_output_dir)
        if path.is_dir(): path = path / "audit-trace.json"
        return load_json(path, f"audit trace {path}")

    def recommend(self, sealed_path: str | Path, metrics_path: str | Path | None = None):
        """Run the optional post-audit recommendation agent only."""
        from forge.agents.recommendation_agent import recommend
        return recommend(sealed_path, metrics_path)

    def narrate_findings(self, sealed_path: str | Path):
        """Create non-evidentiary prose from one verified sealed artifact only."""
        from forge.findings_narrator import narrate_sealed_findings
        return narrate_sealed_findings(sealed_path)

    def seal_results(self, verification_path: str | Path, destination: str | Path | None = None) -> Path:
        data = load_json(verification_path, f"verification manifest {verification_path}")
        findings = tuple(Finding(item["category"], item["epistemic_level"], item["module_path"], item["description"], tuple(Evidence(e["kind"], e["source"], e["detail"], e.get("role", "primary")) for e in item["evidence"]), item["reasoning"], item.get("agent", "bug_investigator"), item.get("outcome", "OBSERVED"), item.get("severity", "MEDIUM"), tuple(item.get("provenance", ())), item.get("controllability", "UNDETERMINED"), item.get("exploitability", "NOT_ASSESSED"), tuple(item.get("occurrences", ()))) for item in data.get("findings", []))
        if not verify_manifest_attestation(data):
            raise ValueError("verification manifest lacks a valid FORGE source attestation")
        manifest = VerificationManifest(data["schema_version"], data["forge_version"], data["hypotheses_schema_version"], data["root"], data["generated_at_epoch"], findings, tuple(data.get("discarded", [])), tuple(data.get("ast_verified_families", [])), tuple(data.get("ast_unverified_families", [])), tuple(data.get("induction", [])), data.get("repository_snapshot_sha256"), data.get("source_attestation"))
        target = Path(destination) if destination else Path(verification_path).with_suffix(Path(verification_path).suffix + ".sealed.json")
        write_sealed_manifest(manifest, target)
        return target

    def generate_report(self, sealed_path: str | Path, mode: str = "standard", destination: str | Path | None = None) -> Path:
        from forge.tiered_report import render_tiered_report
        return render_tiered_report(sealed_path, mode, destination)

    def repository_summary(self, repo: str | Path) -> dict[str, Any]:
        manifest = self.triage_repository(repo)
        return {"repo": manifest.root, "summary": manifest.summary, "modules": len(manifest.modules), "stacks": [item.name for item in manifest.stacks]}
