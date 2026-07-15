"""The single FORGE execution engine.

Frontends may parse arguments or expose tools, but repository auditing and
governance execution live here. The engine is deliberately UI-agnostic.
"""
from __future__ import annotations
import ast
import json
import time
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable

from forge.agents import archaeologist, bug_investigator, integrity_inspector, report_composer, security_auditor
from forge.detector.stack import SKIP_DIRS, discover_files, write_manifest
from forge.evidence_package import build_repository_profile, write_markdown_report, write_repository_profile
from forge.governance.runtime import infer_domains, load_skills, run_skills
from forge.hypotheses import generate_hypotheses, write_hypotheses_manifest
from forge.io import load_json
from forge.severity import severity_for
from forge.models import CoverageReport, Evidence, Finding, ModelRouting, TriageManifest, VerificationManifest
from forge.metrics import collect_metrics
from forge.report import render_report
from forge.reporting import render_dashboard
from forge.sealing import read_and_verify, write_sealed_manifest
from forge.tracing import RuntimeTrace
from forge.verification import verify_hypotheses, write_verification_manifest

def _coverage(root: Path, families=(), discovered=None) -> CoverageReport:
    discovered = discovered if discovered is not None else discover_files(root, include_excluded=True)
    skipped: dict[str, list[str]] = {"excluded_by_policy": [], "syntax_error": [], "binary_or_unreadable": [], "non_python_not_analyzed": []}
    analyzed = 0
    for path in discovered:
        rel = str(path.relative_to(root))
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts): skipped["excluded_by_policy"].append(rel); continue
        try: source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError): skipped["binary_or_unreadable"].append(rel); continue
        if path.suffix != ".py": skipped["non_python_not_analyzed"].append(rel); continue
        try: ast.parse(source)
        except SyntaxError: skipped["syntax_error"].append(rel); continue
        analyzed += 1
    compact = {key: tuple(sorted(value)) for key, value in skipped.items() if value}
    return CoverageReport(len(discovered), analyzed, sum(map(len, compact.values())), compact, tuple(families), Fraction(analyzed, len(discovered) or 1))

def _agent_finding(agent: str, item) -> Finding:
    detail = item.description
    outcome = "PROTOCOL_GAP" if agent == "validate-at-the-boundary" else "OBSERVED"
    return Finding("OBSERVED", "CODE FACT", item.path, detail, (Evidence("source", f"{item.path}:{item.line}", detail),), f"AST detector emitted this observation: {item.family}.", agent, outcome)


def _with_severity(finding: Finding, family: str | None = None) -> Finding:
    return Finding(finding.category, finding.epistemic_level, finding.module_path,
                   finding.description, finding.evidence, finding.reasoning,
                   finding.agent, finding.outcome,
                   severity_for(finding.module_path, finding.epistemic_level, finding.description, finding.agent, family=family))

@dataclass(frozen=True)
class AuditResult:
    repo: str
    connected_alive: int
    findings: int
    discarded: int
    finding_records: tuple[Finding, ...]
    coverage: dict[str, Any]
    artifacts: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "connected_alive": self.connected_alive,
            "findings": self.findings,
            "discarded": self.discarded,
            "finding_records": [asdict(item) for item in self.finding_records],
            "coverage": self.coverage,
            "artifacts": self.artifacts,
        }

class Runtime:
    """Reusable, stateless-per-run FORGE execution engine."""
    def __init__(self, skills_root: str | Path | None = None, max_connected: int = 100,
                 triage_override: Callable | None = None,
                 model_routing: ModelRouting | None = None,
                 cronos_db: str | Path | None = None):
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
        return type(result)(tuple(f for f in result.findings if f.agent == skill_name), result.hypotheses, {path: {skill_name: states.get(skill_name, "NOT_APPLICABLE")} for path, states in result.applicability.items()}, result.limitations)

    def audit(self, repo: str | Path, output_dir: str | Path, max_connected: int | None = None) -> AuditResult:
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
                return self._audit(repo, output_dir, max_connected, trace, cronos)
            except Exception as exc:
                self._event(trace, cronos, "run_failed", exception_type=type(exc).__name__, message=str(exc))
                try:
                    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
                    (out / "audit-trace.json").write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True) + "\n")
                except OSError:
                    pass
                raise

    def _audit(self, repo: str | Path, output_dir: str | Path, max_connected: int | None, trace: RuntimeTrace, cronos=None) -> AuditResult:
        root, out = Path(repo).resolve(), Path(output_dir)
        discovered = discover_files(root, include_excluded=True)
        out.mkdir(parents=True, exist_ok=True)
        started = time.monotonic(); self._event(trace, cronos, "run_started", repository=str(root), max_connected=self.max_connected if max_connected is None else max_connected, model_routing=self.model_routing.to_dict())
        triage_manifest = self.triage_repository(root)
        self._event(trace, cronos, "repository_discovered", modules=len(triage_manifest.modules), stacks=[item.name for item in triage_manifest.stacks])
        self._event(trace, cronos, "modules_classified", summary=triage_manifest.summary, deletion_judgments=triage_manifest.deletion_judgments)
        connected = triage_manifest.summary.get("CONNECTED_ALIVE", 0)
        limit = self.max_connected if max_connected is None else max_connected
        if connected > limit: raise ValueError(f"scope guard: {connected} CONNECTED_ALIVE modules exceeds max_connected={limit}")
        coverage = _coverage(root, discovered=discovered)
        self._event(trace, cronos, "coverage_collected", discovered=coverage.files_discovered, analyzed=coverage.files_analyzed, skipped=coverage.files_skipped, skipped_reasons=coverage.skipped_reasons)
        governance = run_skills(triage_manifest, self.skills_root)
        self._event(trace, cronos, "domain_hypotheses_formed", hypotheses=governance.to_dict()["domain_hypotheses"])
        self._event(trace, cronos, "skill_applicability_evaluated", applicability=governance.applicability)
        self._event(trace, cronos, "skill_contracts_executed", findings=len(governance.findings), limitations=governance.limitations)
        bug = bug_investigator.investigate(triage_manifest, induce=True)
        self._event(trace, cronos, "hypotheses_generated", count=len(bug.hypotheses), modules=list(bug.manifest.audited_modules))
        self._event(trace, cronos, "hypotheses_verified", discarded=len(bug.verification.discarded), findings=len(bug.verification.findings))
        security_result, integrity_result = security_auditor.audit(root), integrity_inspector.inspect(root)
        self._event(trace, cronos, "agent_completed", agent="security_auditor", findings=len(security_result.findings), examinations=security_result.examinations)
        self._event(trace, cronos, "agent_completed", agent="integrity_inspector", findings=len(integrity_result.findings), examinations=integrity_result.examinations)
        findings = [_with_severity(Finding(f.category, f.epistemic_level, f.module_path, f.description, f.evidence, f.reasoning, "bug_investigator", f.outcome)) for f in bug.verification.findings]
        findings += [_with_severity(_agent_finding("security_auditor", item), family=item.family) for item in security_result.findings]
        findings += [_with_severity(_agent_finding("integrity_inspector", item), family=item.family) for item in integrity_result.findings]
        findings += [_with_severity(item) for item in governance.findings]
        for finding in findings:
            self._event(trace, cronos, "finding_emitted", agent=finding.agent, module_path=finding.module_path, category=finding.category, outcome=finding.outcome, description=finding.description, evidence=[asdict(item) for item in finding.evidence])
        self._event(trace, cronos, "hypotheses_discarded", count=len(bug.verification.discarded), records=bug.verification.discarded)
        verification = VerificationManifest("2.0", "0.1.0", bug.verification.hypotheses_schema_version, str(root), int(time.time()), tuple(findings), bug.verification.discarded, bug.verification.ast_verified_families, bug.verification.ast_unverified_families, bug.verification.induction)
        coverage = CoverageReport(coverage.files_discovered, coverage.files_analyzed, coverage.files_skipped, coverage.skipped_reasons, verification.ast_verified_families, coverage.coverage_ratio)
        triage_path, hypotheses_path = out / "triage-manifest.json", out / "hypotheses-manifest.json"
        verification_path, sealed_path, coverage_path = out / "verification-manifest.json", out / "verification-manifest.sealed.json", out / "coverage-report.json"
        skills_path, metrics_path, report_path = out / "skills-runtime.json", out / "metrics.json", out / "forge-report.html"
        profile_path, markdown_path = out / "repository-profile.json", out / "report.md"
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
            "security_auditor": {"findings_per_family": {family: sum(item.family == family for item in security_result.findings) for family in ("hardcoded-credential", "unsafe-deserialization", "path-traversal")}, "examinations": security_result.examinations},
            "integrity_inspector": {"findings_per_family": {family: sum(item.family == family for item in integrity_result.findings) for family in ("decision-adjacent-float", "unversioned-serialization")}, "examinations": integrity_result.examinations},
            "governance_skills": {"loaded": [item["name"] for item in self.list_available_skills()], "findings": len(governance.findings), "applicability_counts": {state: sum(state in values.values() for values in governance.applicability.values()) for state in ("APPLICABLE", "NOT_APPLICABLE", "UNDETERMINED")}},
        }
        metrics = collect_metrics(root=root, discovered=discovered, triage=triage_manifest, coverage=coverage, governance=governance, findings=findings, discarded=verification.discarded, trace=trace, skills=self.list_available_skills(), hypothesis_limitations=bug.manifest.limitations)
        metrics["agent_metrics"] = agent_metrics
        metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
        profile = build_repository_profile(root=str(root), triage=triage_manifest, governance=governance, coverage=coverage, metrics=metrics, findings=findings, elapsed_seconds=time.monotonic() - started)
        write_repository_profile(profile, profile_path)
        self._event(trace, cronos, "metrics_computed", metrics=metrics)
        for name, path in (("triage", triage_path), ("hypotheses", hypotheses_path), ("verification", verification_path), ("coverage", coverage_path), ("skills", skills_path), ("metrics", metrics_path), ("profile", profile_path)):
            self._event(trace, cronos, "artifact_written", artifact=name, path=str(path))
        self._event(trace, cronos, "artifact_written", artifact="report", path=str(report_path))
        self._event(trace, cronos, "seal_created", artifact="sealed", findings=len(findings))
        self._event(trace, cronos, "run_completed", findings=len(findings), elapsed_seconds=str(round(time.monotonic() - started, 6)))
        trace_path = out / "audit-trace.json"
        trace_path.write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True) + "\n")
        write_sealed_manifest(verification, sealed_path, trace.to_dict())
        rendered_reports = render_dashboard(out)
        write_markdown_report(sealed=load_json(sealed_path, f"sealed manifest {sealed_path}"), metrics=metrics, profile=profile, destination=markdown_path)
        artifacts = {"triage": str(triage_path), "hypotheses": str(hypotheses_path), "verification": str(verification_path), "sealed": str(sealed_path), "coverage": str(coverage_path), "skills": str(skills_path), "metrics": str(metrics_path), "profile": str(profile_path), "report": str(report_path), "markdown": str(markdown_path), "trace": str(trace_path), **{key: value for key, value in rendered_reports.items() if key != "report"}}
        if self.cronos_db is not None:
            artifacts["cronos_db"] = str(self.cronos_db)
        return AuditResult(str(root), connected, len(findings), len(verification.discarded), tuple(findings), coverage.to_dict(), artifacts)

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

    def seal_results(self, verification_path: str | Path, destination: str | Path | None = None) -> Path:
        data = load_json(verification_path, f"verification manifest {verification_path}")
        findings = tuple(Finding(item["category"], item["epistemic_level"], item["module_path"], item["description"], tuple(Evidence(e["kind"], e["source"], e["detail"]) for e in item["evidence"]), item["reasoning"], item.get("agent", "bug_investigator"), item.get("outcome", "OBSERVED"), item.get("severity", "MEDIUM")) for item in data.get("findings", []))
        manifest = VerificationManifest(data["schema_version"], data["forge_version"], data["hypotheses_schema_version"], data["root"], data["generated_at_epoch"], findings, tuple(data.get("discarded", [])), tuple(data.get("ast_verified_families", [])), tuple(data.get("ast_unverified_families", [])), tuple(data.get("induction", [])))
        target = Path(destination) if destination else Path(verification_path).with_suffix(Path(verification_path).suffix + ".sealed.json")
        write_sealed_manifest(manifest, target)
        return target

    def generate_report(self, sealed_path: str | Path, mode: str = "standard", destination: str | Path | None = None) -> Path:
        from forge.tiered_report import render_tiered_report
        return render_tiered_report(sealed_path, mode, destination)

    def repository_summary(self, repo: str | Path) -> dict[str, Any]:
        manifest = self.triage_repository(repo)
        return {"repo": manifest.root, "summary": manifest.summary, "modules": len(manifest.modules), "stacks": [item.name for item in manifest.stacks]}
