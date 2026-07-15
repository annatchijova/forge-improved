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

from forge.orchestrator import run_specialized_pipeline
from forge.sealing import verify_sealed
from forge.agents.patch_reviewer import review as review_patch_impl

mcp = FastMCP("forge")

def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}

@mcp.tool()
def audit_repository(path: str, max_connected: int = 100, output_dir: str | None = None) -> dict[str, Any]:
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
        result = run_specialized_pipeline(root, output, max_connected)
        result["report_html_path"] = result["artifacts"]["report"]
        result["ok"] = True
        return result
    except (OSError, ValueError, RuntimeError) as exc:
        return _error("audit_failed", str(exc))

@mcp.tool()
def get_coverage(run_output_dir: str) -> dict[str, Any]:
    path = Path(run_output_dir) / "coverage-report.json"
    try:
        if not path.is_file(): return _error("missing_artifact", f"coverage artifact not found: {path}")
        return {"ok": True, **json.loads(path.read_text(encoding="utf-8"))}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _error("malformed_artifact", f"could not read coverage artifact: {exc}")

@mcp.tool()
def get_findings(run_output_dir: str, agent: str | None = None) -> list | dict:
    path = Path(run_output_dir) / "verification-manifest.sealed.json"
    allowed = {"bug_investigator", "security_auditor", "integrity_inspector"}
    if agent is not None and agent not in allowed: return _error("invalid_agent", f"unsupported agent filter: {agent}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data.get("chain"), list): return _error("malformed_artifact", "sealed manifest has no chain list")
        findings = [entry.get("finding", {}) for entry in data.get("chain", [])]
        if agent is not None: findings = [finding for finding in findings if finding.get("agent", "bug_investigator") == agent]
        return findings
    except FileNotFoundError: return _error("missing_artifact", f"sealed manifest not found: {path}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: return _error("malformed_artifact", f"could not read sealed manifest: {exc}")

@mcp.tool()
def verify_seal(sealed_path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(sealed_path).read_text(encoding="utf-8"))
        return verify_sealed(data)
    except FileNotFoundError: return _error("not_found", f"sealed manifest not found: {sealed_path}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: return _error("malformed_artifact", f"could not verify sealed manifest: {exc}")

@mcp.tool()
def review_patch(unified_diff: str, intent: str, before: str = "", after: str = "") -> dict[str, Any]:
    try: return asdict(review_patch_impl(unified_diff, intent, before, after))
    except (SyntaxError, ValueError) as exc: return _error("invalid_patch", str(exc))

if __name__ == "__main__":
    mcp.run()
