# Hackathon build notes

FORGE is submitted in the **Developer Tools** track. The project was extended
with Codex using GPT-5.6, with product decisions centered on reproducibility,
evidence provenance, bounded execution, and judge-friendly outputs:

* Codex accelerated repository archaeology, test-driven hardening, report UX,
  and the benchmark/evidence-package workflow.
* GPT-5.6 was used as the implementation and review partner; deterministic
  detectors remain in the runtime, so model routing is recorded honestly and
  is never presented as evidence of a model call.
* The project separates observed findings, discarded hypotheses, optional
  recommendations, and applied code changes.

## Submission links

- **Video:** <https://www.youtube.com/watch?v=zdxnPsre31I>
- **Song:** <https://suno.com/song/fe41e51b-4207-4555-a6f7-25cb69851656>
- **License:** [Apache License 2.0](../LICENSE)
- **Technical companion:** <https://forge-technical-companion.vercel.app/>
- **Live preview:** <https://forge-preview-lyart.vercel.app/>
- **Repository with accumulated results:** <https://github.com/annatchijova/forge-results>

## How to use FORGE: four execution modes

All four modes call the same canonical `forge.Runtime`. They differ only in
how an audit is started and how a caller consumes the result. Discovery,
detector scope, hypothesis handling, sealing, and verification stay in local,
deterministic code. A model is optional and never becomes the authority over a
finding.

### 1. CLI — a deterministic local audit

The CLI is the simplest path for a developer, a CI job, or a judge cloning the
repository. The core package has no API key requirement and does not need an
LLM or internet access for the audit itself.

```bash
git clone https://github.com/annatchijova/forge.git
cd forge
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

# Run one bounded audit against a repository.
python3 -m forge audit /path/to/repository \
  -o forge-run \
  --max-connected 100

# Verify the sealed artifact independently.
python3 -m forge verify forge-run/verification-manifest.sealed.json
```

The output directory contains the machine-readable JSON evidence, coverage and
trace artifacts, the SHA-256 sealed verification manifest, and self-contained
HTML/Markdown reports. For a large repository, run `preflight` first and use
`--summary` to keep terminal output short while retaining the complete package
on disk:

```bash
python3 -m forge preflight /path/to/repository --max-connected 100 \
  > /tmp/forge-preflight.json
python3 -m forge audit /path/to/repository -o /tmp/forge-run \
  --max-connected 100 --summary
```

### 2. Python API — embed the same runtime

Use the Python API when FORGE belongs inside another test harness, developer
tool, or scripted workflow. It returns the same typed result and writes the
same evidence package as the CLI:

```python
from forge import Runtime

result = Runtime().audit("/path/to/repository", "forge-run")
print(result.disposition)
```

The optional `max_connected` bound can be passed to `Runtime(...)`. Callers can
then inspect the result in Python or open the generated reports. This is an
embedding option, not a second decision engine.

### 3. MCP — use FORGE from an MCP client

MCP exposes the runtime as tools for Codex, Claude Code, or another compatible
client. Install the optional SDK and start the stdio server from the checkout:

```bash
python -m pip install -e ".[mcp]"
python3 -m forge.mcp_server
```

Register that command in the MCP client with `PYTHONPATH` pointing to the
checkout. The server provides repository audit, coverage, findings, report,
sealing, and seal-verification operations. Optional presentation and proposal
tools are clearly separated from the deterministic finding path; narration is
not evidence and cannot change severity, disposition, or findings.

FORGE also ships an optional `forge-loop` MCP server for bounded remediation
experiments:

```bash
python3 -m forge.loop_mcp
```

The loop consumes sealed evidence, can prepare a bounded proposal or human
patch, and requires FORGE to re-audit the resulting worktree. It never treats a
model's suggestion as a resolved defect. MCP is a long-running process, so
restart it after source changes; `runtime_info()` reports the loaded runtime
fingerprint.

### 4. Multi-agent orchestrator — one governed specialist run

The orchestrator is the compatibility frontend for a specialist audit. It
coordinates the Archaeologist, Bug Investigator, Security Auditor, and
Integrity Inspector, then merges their bounded outputs into one canonical,
sealed result:

```bash
python3 -m forge.orchestrator /path/to/repository \
  -o forge-run \
  --max-connected 100
```

The same path is available to Python callers:

```python
from forge.orchestrator import run_specialized_pipeline

result = run_specialized_pipeline("/path/to/repository", "forge-run")
```

For work produced by independent external agents, use
`forge.multi_agent.finalize_multi_agent_run(...)` to assemble the evidence.
FORGE checks agent independence and provenance, preserves an external layer as
`UNATTESTED` when it cannot attest its analytical origin, and abstains instead
of silently promoting unverified claims. The orchestrator therefore provides
coordination, not open-ended delegated judgment.

### Choosing a mode

Use the **CLI** for a first local run or CI, the **Python API** for embedding,
**MCP** when an interactive agent needs governed tools, and the
**multi-agent orchestrator** when you want the named specialist pipeline. The
evidence model and verification contract are the same in all four cases.

## Twenty governance skills

FORGE keeps 20 documented engineering and governance skills in `skills-gpt/`.
Together they define how the runtime reasons, audits, patches, preserves
evidence, and communicates uncertainty.

| # | Skill | Category | Activates when |
|---:|---|---|---|
| 1 | `abductive-engineering` | Core reasoning | Debugging, root-cause analysis, incident response, or architectural decisions under uncertainty. |
| 2 | `red-team-auditing` | Core reasoning | Security audits, adversarial review, threat modeling, or invariant analysis. |
| 3 | `secure-by-construction` | Core reasoning | Writing, extending, refactoring, or reviewing code with security boundaries. |
| 4 | `software-archaeology` | Core reasoning | Modifying legacy, inherited, or unfamiliar code without breaking behavior. |
| 5 | `diagnosing-bugs` | Core reasoning | Investigating hard bugs and performance regressions through controlled probes and regression tests. |
| 6 | `codebase-health-assessment` | Core reasoning | Classifying dead, fossil, live, and out-of-scope modules before changing a codebase. |
| 7 | `reverse-engineering` | Core reasoning | Reconstructing undocumented systems, binaries, protocols, file formats, or opaque APIs without readable source. |
| 8 | `daubert-defensible-writing` | Core reasoning | Writing findings and reports that separate evidence, inference, uncertainty, and opinion. |
| 9 | `deterministic-core` | Determinism & integrity | Producing bit-for-bit reproducible and tamper-evident decisions with canonical serialization and SHA-256 sealing. |
| 10 | `llm-out-of-the-loop` | Determinism & integrity | Keeping consequential decisions outside the LLM path and sealing results before optional narration. |
| 11 | `tamper-evident-audit-chain` | Determinism & integrity | Building or verifying append-only logs that detect alteration, insertion, reordering, or deletion. |
| 12 | `atomic-state-mutation` | Determinism & integrity | Making multi-write persistent operations all-or-nothing and isolated from concurrent callers. |
| 13 | `versioned-schema-evolution` | Determinism & integrity | Evolving serialized artifacts with explicit schema versions without breaking existing data. |
| 14 | `surgical-patcher` | Patching & editing | Applying anchored, verified, reversible changes instead of rewriting entire source files. |
| 15 | `audit-before-patch` | Patching & editing | Validating an audit finding against the current file before changing any code. |
| 16 | `validate-at-the-boundary` | Input & data | Validating untrusted input at the system boundary with clear errors. |
| 17 | `honest-degradation` | Input & data | Handling degraded, legacy, reconstructed, or unverifiable input without returning plausible-looking wrong results. |
| 18 | `sql-aggregation-not-materialization` | Input & data | Pushing counts, sums, and grouping into the database instead of loading rows into memory. |
| 19 | `git-discipline` | Process | Keeping AI-assisted coding sessions recoverable, reviewable, and free from unsafe history rewriting. |
| 20 | `claim-provenance-discipline` | Evidence governance | Preserving each claim's origin, epistemic level, scope bound, and falsifier across summaries and handoffs. |

### Runtime status of the skills

The 20 skills are the documented governance catalog. The executable runtime
currently has contracts for a smaller subset, including
`validate-at-the-boundary`, `honest-degradation`, `deterministic-core`,
`atomic-state-mutation`, `sql-aggregation-not-materialization`, and
`tamper-evident-audit-chain`. The remaining skills are recorded as
process-level obligations and methodology documents rather than being
pretended to be per-module scanners.

Before submission, provide the actual Codex `/feedback` Session ID for the
build thread in the submission form. FORGE does not fabricate or hard-code
that external identifier.

## Codex build-session evidence

Known Codex sessions used during the build:

* `019f65d2-230f-71d2-ab70-e8195fb8fae0`
* `019f6693-c5fa-75e1-bc61-3c7af5ab6cc0`
* `019f6706-b195-7981-b21a-a01f98a6f785`
* _Three additional session IDs pending retrieval from screenshots._
