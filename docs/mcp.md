# MCP integration

FORGE exposes its runtime through MCP as a first-class frontend, alongside the
Python API and the CLI. MCP transport is in `forge/mcp_server.py`. It exposes
`audit_repository`, `get_coverage`, `get_findings`, `verify_seal`, the optional
`recommend_changes`, `narrate_findings`, and the standalone `review_patch` tool. It changes **how**
FORGE is invoked, not **how** FORGE reasons.

`narrate_findings(sealed_path)` is presentation-only: it verifies one sealed
finding manifest before producing deterministic reader-oriented prose. That
prose is visibly marked as **not verified**, is not part of the seal, and
cannot alter findings, severity, disposition, or the audit decision.

## Stale-process detection: `runtime_info()`

Unlike the CLI, which re-imports from disk on every invocation, the MCP
server is a long-running process: it keeps whatever was on disk at process
start loaded in memory for its entire lifetime. A source fix applied after
the server started is real on disk and invisible to that process until it
restarts, with nothing in its responses distinguishing "the fix does not
work" from "this process has not loaded it yet." Found via a real stress-test
session where a fix appeared to have no effect through MCP, and turned out to
be a server process that had been running since before the fix landed.

Call `runtime_info()` to see what this server process actually has loaded
(`runtime_fingerprint`, a hash of the mtime/size of every `.py` file under
`forge/` at import time — not a manually maintained version string, so it
changes automatically after any source change once the process restarts).
The same fingerprint also travels inside every `audit_repository()` result,
under `metrics.reproducibility.runtime_fingerprint` — compare it against a
fresh CLI run over the same repository, or against `runtime_info()` again
after a restart, to confirm a fix actually took effect. There is no hot
reload; a changed fingerprint after a restart is the only way to tell.

## Running the MCP server

With the Python MCP SDK installed, start the stdio server with:

```bash
python3 -m forge.mcp_server
```

## Claude Code integration

FORGE's primary integration and demo path is the Codex/orchestrator runtime:
the orchestrator invokes the FORGE audit MCP, and the existing CRONOS runtime
records the execution trace. Claude Code is also supported as an MCP client,
but it is an alternative consumer of the same read-only audit tools — not a
replacement for FORGE's deterministic authority and not the primary
orchestration path.

From Claude Code, register the audit server with a stable absolute path to the
FORGE checkout:

```bash
claude mcp add forge --scope user \
  --env PYTHONPATH=/absolute/path/to/forge \
  -- python3 -m forge.mcp_server
```

Register the optional proposal loop separately when it is wanted:

```bash
claude mcp add forge-loop --scope user \
  --env PYTHONPATH=/absolute/path/to/forge \
  -- python3 -m forge.loop_mcp
```

Verify the registrations with:

```bash
claude mcp list
claude mcp get forge
claude mcp get forge-loop
```

For a project-shared configuration, use `--scope project`; Claude Code stores
that configuration in `.mcp.json`, which should be reviewed before committing
because it grants the project access to the declared local server. The
equivalent configuration is:

```json
{
  "mcpServers": {
    "forge": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "forge.mcp_server"],
      "env": {"PYTHONPATH": "/absolute/path/to/forge"}
    },
    "forge-loop": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "forge.loop_mcp"],
      "env": {"PYTHONPATH": "/absolute/path/to/forge"}
    }
  }
}
```

The audit server exposes repository, ref, comparison, coverage, findings,
sealing, and report operations. The loop server is optional and consumes that
evidence: it works in a zero-credit deterministic/human-patch mode and keeps
LLM proposal adapters outside the FORGE decision boundary. Nothing is resolved
until FORGE re-audits the temporary worktree.
