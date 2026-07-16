"""FastMCP transport for the existing FORGE pipeline.

The tool functions are ordinary Python functions as well, which keeps fixture
tests independent of a running MCP client. They never write to an audited
repository; audit output is placed in a temporary directory outside it.
"""
from __future__ import annotations
import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from forge.runtime import Runtime
from forge.models import ModelRouting
from forge.sealing import verify_sealed
from forge.agents.patch_reviewer import review as review_patch_impl
from forge.comparison import compare_runs
from forge.agent_independence import load_and_validate, write_validation_artifact, AgentIndependenceError
from forge.multi_agent import finalize_multi_agent_run
from forge.build_info import RUNTIME_FINGERPRINT, PROCESS_IMPORTED_AT_EPOCH

mcp = FastMCP("forge")
runtime = Runtime()

def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}

@mcp.tool()
def runtime_info() -> dict[str, Any]:
    """Report which FORGE source this server process actually has loaded.

    Unlike the CLI (`python3 -m forge audit ...`), which re-imports from disk
    on every invocation, this MCP server is a long-running process: it keeps
    whatever was on disk at process start loaded in memory for its entire
    lifetime. A source fix applied after this process started is real on
    disk and invisible here until the process restarts, with no way to tell
    "the fix does not work" from "this process has not loaded it yet" unless
    that is checked explicitly - call this before trusting a fix's absence
    from a result, or compare runtime_fingerprint against a fresh CLI run
    over the same repository. The same fingerprint also travels inside every
    audit_repository() result, under metrics.reproducibility.
    """
    return {
        "ok": True,
        "loaded_from": str(Path(__file__).resolve().parent),
        "runtime_fingerprint": RUNTIME_FINGERPRINT,
        "process_imported_at_epoch": PROCESS_IMPORTED_AT_EPOCH,
    }

@mcp.tool()
def audit_repository(path: str, max_connected: int = 100, output_dir: str | None = None,
                     orchestrator_model: str | None = None,
                     agent_models: dict[str, str] | None = None,
                     cronos_db: str | None = None,
                     induction: bool = True) -> dict[str, Any]:
    """Run the full FORGE governance pipeline against a repository and seal the findings.

    Writes triage, hypotheses, verification, sealed, and coverage artifacts plus an
    HTML report to a temporary directory (or `output_dir` if given). Refuses to run
    past triage if the repository has more than `max_connected` CONNECTED_ALIVE
    modules. Oversized scopes are audited in deterministic shards. Never modifies
    the audited repository. Set induction=false for static-only analysis.
    """
    root = Path(path).expanduser()
    if not root.exists(): return _error("not_found", f"repository path does not exist: {path}")
    if not root.is_dir(): return _error("not_directory", f"repository path is not a directory: {path}")
    try:
        if output_dir is None:
            output = Path(tempfile.mkdtemp(prefix="forge-mcp-"))
        else:
            output_root = Path(output_dir).expanduser()
            output_root.mkdir(parents=True, exist_ok=True)
            output = Path(tempfile.mkdtemp(prefix="run-", dir=output_root))
        configured_runtime = Runtime(max_connected=max_connected, model_routing=ModelRouting(orchestrator_model, agent_models or {}), cronos_db=cronos_db, induction=induction)
        result = configured_runtime.audit(root, output).to_dict()
        result["report_html_path"] = result["artifacts"]["report"]; result["ok"] = True
        return result
    except (OSError, ValueError, RuntimeError) as exc:
        return _error("audit_failed", str(exc))

@mcp.tool()
def audit_ref(path: str, ref: str, max_connected: int = 100, output_dir: str | None = None,
              keep_checkout: bool = False) -> dict[str, Any]:
    """Audit a committed Git branch, tag, or commit without changing the repository."""
    root = Path(path).expanduser()
    if not root.exists(): return _error("not_found", f"repository path does not exist: {path}")
    if not root.is_dir(): return _error("not_directory", f"repository path is not a directory: {path}")
    try:
        if output_dir is None:
            output = Path(tempfile.mkdtemp(prefix="forge-mcp-ref-"))
        else:
            output_root = Path(output_dir).expanduser()
            output_root.mkdir(parents=True, exist_ok=True)
            output = Path(tempfile.mkdtemp(prefix="run-", dir=output_root))
        result = Runtime(max_connected=max_connected).audit_ref(root, ref, output, keep_checkout=keep_checkout).to_dict()
        result["ok"] = True
        return result
    except (OSError, ValueError, RuntimeError) as exc:
        return _error("audit_ref_failed", str(exc))

@mcp.tool()
def compare_refs(path: str, base_ref: str, head_ref: str, max_connected: int = 100,
                 output_dir: str | None = None) -> dict[str, Any]:
    """Audit two committed Git refs and report new, fixed, and pre-existing findings."""
    root = Path(path).expanduser()
    if not root.exists(): return _error("not_found", f"repository path does not exist: {path}")
    if not root.is_dir(): return _error("not_directory", f"repository path is not a directory: {path}")
    try:
        output = Path(output_dir).expanduser() if output_dir is not None else Path(tempfile.mkdtemp(prefix="forge-mcp-compare-"))
        return {"ok": True, **Runtime(max_connected=max_connected).compare_refs(root, base_ref, head_ref, output)}
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return _error("compare_refs_failed", str(exc))

@mcp.tool()
def get_coverage(run_output_dir: str) -> dict[str, Any]:
    """Read the coverage-report.json artifact from a prior audit_repository() run.

    Reports files_discovered/analyzed/skipped and the exact reason each skipped
    file was excluded, so the arithmetic can be checked (discovered == analyzed
    + sum of skipped_reasons).
    """
    path = Path(run_output_dir) / "coverage-report.json"
    try:
        if not path.is_file(): return _error("missing_artifact", f"coverage artifact not found: {path}")
        return {"ok": True, **json.loads(path.read_text(encoding="utf-8"))}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _error("malformed_artifact", f"could not read coverage artifact: {exc}")

@mcp.tool()
def get_findings(run_output_dir: str, agent: str | None = None) -> list | dict:
    """List findings from a prior audit_repository() run's sealed manifest.

    Optionally filter to one agent ("bug_investigator", "security_auditor", or
    "integrity_inspector"). Each finding carries category, epistemic_level,
    module_path, description, evidence, and reasoning.
    """
    path = Path(run_output_dir) / "verification-manifest.sealed.json"
    allowed = {"bug_investigator", "security_auditor", "integrity_inspector"}
    if agent is not None and agent not in allowed: return _error("invalid_agent", f"unsupported agent filter: {agent}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data.get("chain"), list): return _error("malformed_artifact", "sealed manifest has no chain list")
        return runtime.get_findings(run_output_dir, agent)
    except FileNotFoundError: return _error("missing_artifact", f"sealed manifest not found: {path}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: return _error("malformed_artifact", f"could not read sealed manifest: {exc}")

@mcp.tool()
def verify_seal(sealed_path: str) -> dict[str, Any]:
    """Verify a sealed verification manifest's SHA-256 hash chain for tampering.

    Confirms findings were not altered after sealing; it does not confirm the
    findings themselves are correct, and it is not a defense against a full
    cascade forgery (see DECISIONS.md).
    """
    try:
        return runtime.verify_findings(sealed_path)
    except FileNotFoundError: return _error("not_found", f"sealed manifest not found: {sealed_path}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: return _error("malformed_artifact", f"could not verify sealed manifest: {exc}")

@mcp.tool()
def compare_audits(previous_run_dir: str, current_run_dir: str) -> dict[str, Any]:
    """Compare two verified FORGE runs and report resolved, new, unchanged, and coverage delta."""
    try:
        return {"ok": True, **compare_runs(previous_run_dir, current_run_dir)}
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        return _error("comparison_failed", str(exc))

@mcp.tool()
def validate_agent_results(results_dir: str, required_agents: list[str]) -> dict[str, Any]:
    """Fail closed unless external agent files contain distinct evidence-backed work products."""
    try:
        return {"ok": True, **load_and_validate(results_dir, required_agents)}
    except (AgentIndependenceError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        return _error("independence_rejected", str(exc))

@mcp.tool()
def finalize_agent_results(results_dir: str, required_agents: list[str], output_path: str | None = None) -> dict[str, Any]:
    """Validate external work products and write the mandatory closing artifact."""
    try:
        return {"ok": True, **write_validation_artifact(results_dir, required_agents, output_path)}
    except (AgentIndependenceError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        return _error("independence_rejected", str(exc))

@mcp.tool()
def finalize_multi_agent_run_artifacts(run_dir: str, required_agents: list[str], external_findings_path: str | None = None, native_sealed_path: str | None = None, agent_results_dir: str | None = None) -> dict[str, Any]:
    """Create one canonical finding set and seal it after independence validation."""
    try:
        return {"ok": True, **finalize_multi_agent_run(run_dir, required_agents, external_findings_path, native_sealed_path, agent_results_dir)}
    except (AgentIndependenceError, FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        return _error("canonicalization_rejected", str(exc))

@mcp.tool()
def triage_repository(path: str) -> dict[str, Any]:
    """Classify every module in a repository without running hypotheses or findings.

    Returns the TriageManifest: each module's language, module_class
    (CONNECTED_ALIVE / FOSSIL_HIGH_RISK / FOSSIL_LOW_RISK / DEAD_WEIGHT / DUPLICATE),
    caller/import counts, and detected stacks. Read-only, no artifacts written.
    """
    root = Path(path).expanduser()
    if not root.is_dir(): return _error("invalid_repository", f"repository path is not a directory: {path}")
    try:
        manifest = runtime.triage_repository(root)
        return {"ok": True, "manifest": manifest.to_dict()}
    except (OSError, ValueError) as exc: return _error("triage_failed", str(exc))

@mcp.tool()
def infer_module_domains(path: str) -> dict[str, Any]:
    """Guess each module's domain (machine_learning, input_boundary, cryptographic) from source patterns.

    Evidence-backed hypotheses per module, not repository-wide facts; a module
    with no matching pattern gets zero confidence rather than a forced guess.
    Used internally to decide which governance skills apply to which module.
    """
    root = Path(path).expanduser()
    if not root.is_dir(): return _error("invalid_repository", f"repository path is not a directory: {path}")
    try:
        hypotheses = runtime.infer_module_domains(root)
        return {"ok": True, "hypotheses": [{"module_path": h.module_path, "domains": h.domains, "confidence": {"numerator": h.confidence.numerator, "denominator": h.confidence.denominator}, "evidence": [item.__dict__ for item in h.evidence], "alternatives": h.alternatives} for h in hypotheses]}
    except (OSError, ValueError) as exc: return _error("domain_inference_failed", str(exc))

@mcp.tool()
def list_available_skills() -> dict[str, Any]:
    """List the governance skill plugins loaded from forge/skills/, with their contracts."""
    try: return {"ok": True, "skills": list(runtime.list_available_skills())}
    except (OSError, ValueError, json.JSONDecodeError) as exc: return _error("skill_loading_failed", str(exc))

@mcp.tool()
def run_skill(path: str, skill: str | None = None) -> dict[str, Any]:
    """Run one governance skill (or all loaded skills if `skill` is omitted) against a repository.

    A failing skill is isolated: it is recorded as "ERROR" in the per-module
    applicability map with a limitation note, and does not stop other skills
    or other modules from being evaluated.
    """
    root = Path(path).expanduser()
    if not root.is_dir(): return _error("invalid_repository", f"repository path is not a directory: {path}")
    try: return {"ok": True, **runtime.run_skill(root, skill).to_dict()}
    except (OSError, ValueError) as exc: return _error("skill_run_failed", str(exc))

@mcp.tool()
def repository_summary(path: str) -> dict[str, Any]:
    """Get a quick, cheap overview of a repository (module counts by class, detected stacks).

    Lighter-weight than audit_repository(): no hypotheses, findings, or sealing.
    """
    root = Path(path).expanduser()
    if not root.is_dir(): return _error("invalid_repository", f"repository path is not a directory: {path}")
    try: return {"ok": True, **runtime.repository_summary(root)}
    except (OSError, ValueError) as exc: return _error("summary_failed", str(exc))

@mcp.tool()
def get_audit_trace(run_output_dir: str) -> dict[str, Any]:
    try: return {"ok": True, "trace": runtime.get_audit_trace(run_output_dir)}
    except FileNotFoundError: return _error("missing_artifact", f"audit trace not found: {run_output_dir}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: return _error("malformed_artifact", str(exc))

@mcp.tool()
def recommend_changes(sealed_path: str, metrics_path: str | None = None) -> dict[str, Any]:
    """Generate optional post-audit suggestions without rescanning or patching the repository."""
    try:
        return {"ok": True, "recommendations": [asdict(item) for item in runtime.recommend(sealed_path, metrics_path)]}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _error("recommendation_failed", str(exc))

@mcp.tool()
def narrate_findings(sealed_path: str) -> dict[str, Any]:
    """Create non-evidentiary prose from one verified sealed finding artifact.

    The tool only reads the manifest, verifies it first, and cannot alter the
    audit decision, finding severity, or sealed evidence.
    """
    try:
        return {"ok": True, "summary": runtime.narrate_findings(sealed_path).to_dict()}
    except FileNotFoundError:
        return _error("not_found", f"sealed manifest not found: {sealed_path}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _error("narration_failed", str(exc))

@mcp.tool()
def generate_report(sealed_path: str, mode: str = "standard", output: str | None = None) -> dict[str, Any]:
    """Render a self-contained HTML forensic report from a sealed verification manifest.

    `mode` selects the report tier (e.g. "standard" or "summary"); `output`
    defaults to a path next to `sealed_path` if not given.
    """
    try: return {"ok": True, "path": str(runtime.generate_report(sealed_path, mode, output))}
    except (OSError, ValueError, json.JSONDecodeError) as exc: return _error("report_failed", str(exc))

@mcp.tool()
def seal_results(verification_path: str, output: str | None = None) -> dict[str, Any]:
    """Seal a FORGE-attested verification manifest into a SHA-256 chain.

    Only manifests emitted by this FORGE process are accepted. This prevents a
    caller from presenting arbitrary JSON as a genuine FORGE audit. `output`
    defaults to a path next to `verification_path` if not given.
    """
    try: return {"ok": True, "path": str(runtime.seal_results(verification_path, output))}
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc: return _error("seal_failed", str(exc))

@mcp.tool()
def review_patch(unified_diff: str, intent: str, before: str = "", after: str = "") -> dict[str, Any]:
    """Review a single unified diff against a stated intent (not a repository scan).

    Reports changed_lines, which functions/classes were touched, the ratio of
    changed lines to touched-scope size (as an exact fraction), and flags when
    the change falls outside any function/class or doesn't match the stated intent.
    """
    try:
        result = asdict(review_patch_impl(unified_diff, intent, before, after))
        result["ratio"] = {"numerator": result["ratio"].numerator, "denominator": result["ratio"].denominator}
        return result
    except (SyntaxError, ValueError) as exc: return _error("invalid_patch", str(exc))

if __name__ == "__main__":
    mcp.run()
