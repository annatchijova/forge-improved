# FORGE

Forensic Repository Governance Engine.

## Development

Run all commands (`pytest`, `python3 -m forge`, and Git operations) from the
repository root: `/home/labestiadevigia/forge`. Running from a parent directory
can pick up unrelated files and produce misleading test or audit results. This
happened during the Kimi audit verification step.

## Shared skills

The versioned `skills-gpt/` directory contains the project's shared engineering
and audit policies. Future specialized agents and the multi-agent orchestrator
will use these documents as common operating context rather than inventing
separate standards.

The collection is designed for repository analysis across conventional code,
floating-point decision logic, and ML systems. It keeps observation, inference,
and judgment separate; uses Peircean abduction to propose explanations,
deduction to derive testable consequences, and induction only for claims backed
by repeated evidence. Deterministic sealing and exact arithmetic are preferred
where results become evidence; floats and probabilistic ML outputs remain
explicitly bounded, labeled, and tested at their boundary conditions.

The first local orchestrator is available as `python3 -m forge.orchestrator`.
It is sequential orchestration of specialized-responsibility agents today, not
concurrent or negotiating agents: `run_pipeline()` is a dependency-ordered
call chain. It writes all artifacts to an output directory and stops when
`--max-connected` is exceeded. The guard runs after `triage()` returns, so it
blocks downstream work on broad repositories such as VIGIA but does not remove
triage's own cost. Agent role contracts live in `forge/agents/README.md`. MCP
remains a planned transport integration, not a current dependency.
