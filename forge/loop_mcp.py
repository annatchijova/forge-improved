"""Separate MCP surface for optional patch proposal loops.

The audit MCP remains the evidence producer. This server consumes audit output
through the shared Runtime and never becomes an authority over findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import tempfile

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    class FastMCP:  # type: ignore[no-redef]
        """Fallback when the optional 'mcp' dependency is not installed.

        See forge.mcp_server for the rationale: .tool() must stay an
        identity decorator so this module's plain functions remain
        importable and testable without the 'mcp' package.
        """

        def __init__(self, name: str) -> None:
            self._name = name

        def tool(self):
            def _identity(func):
                return func
            return _identity

        def run(self) -> None:
            raise RuntimeError(
                "The optional 'mcp' dependency is not installed. "
                "Install forge[mcp] to run the MCP server."
            )

from forge.loop import run_loop

mcp = FastMCP("forge-loop")


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}


@mcp.tool()
def loop_audit(path: str, ref: str, proposal_provider: str = "deterministic",
               patches: list[str] | None = None, max_iterations: int = 3,
               max_connected: int = 100, output_dir: str | None = None,
               test_command: list[str] | None = None,
               test_timeout: int = 120) -> dict[str, Any]:
    """Propose patches in isolated worktrees and let FORGE re-audit them.

    ``test_command`` is executed as the MCP caller's requested subprocess in
    the temporary worktree. It is not shell-interpolated, but it still grants
    the caller the ability to execute programs available to the MCP process;
    expose this tool only to callers trusted with equivalent local-shell access.
    """
    root = Path(path).expanduser()
    if not root.exists(): return _error("not_found", f"repository path does not exist: {path}")
    if not root.is_dir(): return _error("not_directory", f"repository path is not a directory: {path}")
    try:
        output = Path(output_dir).expanduser() if output_dir else Path(tempfile.mkdtemp(prefix="forge-loop-mcp-"))
        return {"ok": True, **run_loop(root, ref, output, proposal_provider, patches,
                                         max_iterations, max_connected, test_command, test_timeout)}
    except (OSError, ValueError, RuntimeError) as exc:
        return _error("loop_failed", str(exc))


if __name__ == "__main__":
    mcp.run()
