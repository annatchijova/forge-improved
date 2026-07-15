# FORGE

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Architecture](https://img.shields.io/badge/architecture-multi--agent-darkgreen)
![Deterministic](https://img.shields.io/badge/decision%20path-deterministic-success)
![Audit](https://img.shields.io/badge/audit-SHA--256%20sealed-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

> **Forensic Repository Governance Engine**
>
> A deterministic multi-agent system for repository governance, forensic
> software engineering, architectural archaeology, and evidence-driven code
> review.

---

## Why FORGE?

Modern AI coding assistants are excellent at producing code.

They are considerably less disciplined at explaining **why** something is a
defect, distinguishing evidence from speculation, documenting discarded
hypotheses, or proving what was actually inspected.

FORGE addresses that gap.

Rather than behaving like another autonomous coding agent, FORGE behaves like
a forensic engineering team:

* observes before concluding,
* generates competing hypotheses,
* actively attempts to falsify them,
* reports both findings and discarded explanations,
* seals the complete audit trail.

Model routing is explicit and shared by the CLI, MCP, and Python runtime. The
built-in detectors remain deterministic and do not invoke models yet; routing
is recorded in the audit trace so a future model-backed stage cannot hide its
provider choice:

```bash
python3 -m forge audit /path/to/repo \
  --orchestrator-model large-model \
  --agent-model bug_investigator=small-model \
  --agent-model security_auditor=small-model
```

The same configuration is available through `Runtime(model_routing=...)` and
the MCP `audit_repository` tool. An agent model name is configuration metadata
until that agent has a model-backed implementation; it is never presented as
evidence that a model was called.

For a full execution trace, enable the optional CRONOS runtime store:

```bash
python3 -m forge audit /path/to/repository \
  --output-dir forge-run \
  --cronos-db forge-run/cronos.sqlite3
```

The repository remains read-only. The SQLite database is an output artifact
owned by FORGE, not a file written into the audited repository unless the
caller explicitly chooses such an output location.

The objective is not simply finding more bugs.

The objective is producing findings that another engineer can independently
reproduce, challenge, or verify.

## The cost advantage: measured, not marketed

FORGE's normal audit path keeps the decision mechanism out of the LLM loop.
Repository discovery, AST parsing, structural detectors, hypothesis handling,
sealing, and report generation run as local deterministic code. The configured
model names are routing metadata until a model-backed implementation actually
calls a model; they are never evidence that a model was used.

That makes the operational cost scale with repository work and local CPU time,
not with the number of source tokens sent to a model. It also makes repeated
runs reproducible: the same sealed inputs and detector version produce the same
decision path. Dynamic induction is real process execution with a timeout, not
an LLM request.

### Mutante: first measured run

The Mutante audit analyzed 43 modules and consumed **6 Codex session credits**
as observed from the session balance (2348 → 2342). This is a measured
orchestration/session cost, not a claim that every environment will display the
same price. The built-in FORGE detectors did not call an LLM during that audit;
the credits include the surrounding Codex orchestration and interpretation.

| Run | Repository work | Observed session cost | Model-backed detector calls | Evidence |
|---|---:|---:|---:|---|
| Mutante | 43 analyzed modules / 308 discovered files | **6 credits** | 0 in the built-in audit path | session balance + `metrics.json` + sealed trace |

After every benchmark or repository audit, record the same fields next to the
run artifacts:

```text
run: <run id>
repository: <name>
files/modules: <analyzed>/<discovered>
credits_before: <balance>
credits_after: <balance>
credits_consumed: <difference>
model_backed_detector_calls: <measured count or unknown>
source: <session UI / provider meter / runtime instrumentation>
```

This distinction is important for the hackathon pitch: **FORGE's audit
decisions are deterministic and token-light by architecture; building new
detectors, orchestrating the session, optional natural-language narration, and
future model-backed stages can still consume credits.** We report those costs
instead of hiding them behind an attractive headline.

---

## Architecture at a glance

FORGE is not a single script that scans a repository and prints findings. It
is a small set of layers, each with one job, composed by one runtime:

| Layer | Lives in | Responsibility |
|---|---|---|
| **Core** | `forge/models.py`, `canonical.py`, `sealing.py`, `metrics.py`, `severity.py`, `io.py` | Typed data contracts, canonical serialization, SHA-256 sealing, run metrics |
| **Specialized agents** | `forge/agents/*.py` | Single-responsibility detectors (Archaeologist, Bug Investigator, Security Auditor, Integrity Inspector, Report Composer, Patch Reviewer, Recommendation Agent) |
| **Governance skills** | `forge/governance/runtime.py`, `forge/skills/*` | Executable, versioned contracts loaded by domain applicability, not hardcoded into the core |
| **Harness** | `forge/harness/*.py` | Mines weaknesses from sealed runs, proposes bounded fixes, validates against the real held-in/held-out test suite |
| **Tracing** | `forge/tracing.py`, `forge/cronos/*` | Event-level, tamper-evident record of what the runtime *did*, sealed alongside findings |
| **Orchestration** | `forge/runtime.py`, `orchestrator.py`, `mcp_server.py`, `cli.py` | The single execution engine and its three thin frontends |
| **Reporting** | `forge/report.py`, `tiered_report.py` | Self-contained HTML at multiple detail tiers |

No agent reasons on another agent's behalf, and the orchestrator does not
delegate open-ended judgment to anything: **each agent has a verifiable
responsibility and an explicit contract. The runtime coordinates a pipeline
in which hypotheses, evidence, and conclusions stay visibly separate** —
never a single black box that says "trust me, I found a bug."

---

## Engineering philosophy

FORGE is built around one principle:

> **Engineering should optimize for correctness before confidence.**

Every repository audit follows the Peircean reasoning loop:

```
Observation
      │
      ▼
Abduction
(generate hypotheses)
      │
      ▼
Deduction
(design falsification tests)
      │
      ▼
Induction
(earn only bounded conclusions)
```

A plausible pattern is never promoted into a defect merely because it looks
convincing. Evidence remains separate from inference throughout the entire
pipeline: every finding carries an explicit epistemic level from the
red-team-auditing vocabulary — **CODE FACT** for a directly observed AST
match, **PLAUSIBLE HYPOTHESIS** for an unexecuted abduction, **CONFIRMED BY
INDUCTION** for a reproduced prediction, **FALSIFIED** for a refuted one —
and that level is never invented or conflated with the OBSERVED / INFERRED /
OPINION category field it sits next to.

---

## Multi-agent architecture

FORGE contains seven specialized, single-responsibility agent modules. Five
participate in the normal repository audit; Patch Reviewer and Recommendation
Agent are deliberately kept optional and post-audit. Report Composer renders
the result but does not invent findings.

```
                          Repository
                              │
                              ▼
                    ┌──────────────────┐
                    │  ARCHAEOLOGIST   │
                    │  triage + module │
                    │  classification  │
                    └──────────────────┘
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
   ┌────────────────┐ ┌───────────────┐ ┌────────────────────┐
   │ BUG INVESTIGATOR│ │SECURITY AUDITOR│ │INTEGRITY INSPECTOR │
   │ hypothesis gen. │ │ AST security   │ │ determinism +      │
   │ + AST-verified  │ │ pattern checks │ │ schema-versioning  │
   │ adversarial test│ │                │ │ checks             │
   └────────────────┘ └───────────────┘ └────────────────────┘
              │               │                │
              └───────────────┼────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  merge + seal    │
                    │  SHA-256 chain   │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ REPORT COMPOSER  │
                    │ HTML forensic    │
                    │ report           │
                    └──────────────────┘

   ┌─────────────────────────────────────────────────────┐
   │ PATCH REVIEWER — optional, evaluates a single diff   │
   │ against its stated intent. Not part of the repo scan.│
   └─────────────────────────────────────────────────────┘
```

Each agent has a strictly bounded responsibility. No agent silently changes
another agent's conclusions: findings are merged into one
`VerificationManifest`, sealed once, and rendered once.

---

## Unified runtime and frontends

`forge.Runtime` is the single execution engine. It owns discovery, triage,
domain hypotheses, executable skill contracts, findings, sealing, and report
artifacts. The four supported frontends are thin adapters over this same
engine:

| Mode | Entry point | Use case |
|---|---|---|
| **Python API** | `from forge import Runtime` | Embed an audit in Python code or tests. |
| **CLI** | `python3 -m forge audit ...` | Run audits and render reports from a shell or CI job. |
| **Orchestrator** | `python3 -m forge.orchestrator ...` | Use the backward-compatible orchestration entry point. |
| **MCP** | `python3 -m forge.mcp_server` | Expose the same operations through MCP tools. |

CI is an invocation environment, not a fifth FORGE frontend: the CLI can run
inside CI, and CI configuration is only reported as a detected repository
stack when present.

```python
from forge import Runtime
result = Runtime().audit("/path/to/repository", "forge-run")
```

The fully automated CLI is:

```bash
python3 -m forge audit /path/to/repository -o forge-run --max-connected 100
```

Every audit produces an evidence package in the output directory:
`forge-report.html` (interactive), `report.md`, `repository-profile.json`,
`metrics.json`, `audit-trace.json`, `coverage-report.json`, and the sealed
verification manifest. JSON artifacts are the machine-readable source; HTML
and Markdown are presentation layers over those artifacts.

The visual package is generated automatically by the public reporting module:

```python
from forge import render_dashboard

paths = render_dashboard("forge-run")
```

This writes the main WOW-effect dashboard plus `summary`, `standard`, and
`extended` HTML tiers and the structured `json` mode. The four projections are
derived from the same sealed manifest, so presentation cannot silently change
the findings. A normal `Runtime().audit(...)` run invokes this renderer
automatically; no second reporting command is required.

### Large-repository demo mode

For a large repository, do one discovery-only preflight before the expensive
audit. It reports the connected-module count and checks the scope guard without
producing findings or changing the target repository:

```bash
python3 -m forge preflight /path/to/large-repository --max-connected 100 \
  > /tmp/forge-preflight.json
```

Then run the audit once, with artifacts outside the target repository and
compact stdout. `--summary` avoids printing every finding into a terminal,
chat transcript, or CI log; the complete evidence remains on disk:

```bash
python3 -m forge audit /path/to/large-repository \
  -o /tmp/forge-large-demo \
  --max-connected 100 \
  --summary > /tmp/forge-large-demo-summary.json
```

If preflight reports more connected modules than the selected limit, choose an
explicitly bounded higher limit before the one full run. Do not silently treat
the scope guard as full-repository coverage. For Git repositories, each
finding's HTML/Markdown evidence includes the source commit when `git blame`
is available; unavailable blame is labeled rather than inferred.

### Reproducible benchmark corpus

Place local repositories under a corpus directory and run:

```bash
python3 -m forge benchmark benchmarks/ -o benchmark-run/ --max-connected 100
```

FORGE audits each detected repository through the same `Runtime`, then writes
`benchmark.json` and `benchmark.html` with findings, discarded hypotheses,
coverage percentage, elapsed time, connected modules, and status. It does not
modify corpus repositories. The corpus can contain deterministic, parser,
web, ML, crypto, and legacy fixtures without special cases in the engine.

MCP exposes the same runtime through triage, domain inference, skill
listing/execution, audit, sealing, verification, and report tools.
`run_pipeline()` and `run_specialized_pipeline()` remain compatibility wrappers
around `Runtime.audit()` for Python callers and the orchestrator frontend.

### `forge.orchestrator.run_pipeline()` — the original 5-stage pipeline

The module-1-through-5 pipeline (triage → hypothesis generation →
adversarial verification → sealing → reporting) as one dependency-ordered
call chain. Runnable via `python3 -m forge.orchestrator`.

### `forge.orchestrator.run_specialized_pipeline()` — the automatic audit pipeline

Runs Archaeologist, Bug Investigator, Security Auditor and Integrity
Inspector, merges and seals their findings into a single `VerificationManifest`
(`schema_version="2.0"`), and renders one HTML report that also carries a
coverage breakdown. Called from Python today (`from forge.orchestrator import
run_specialized_pipeline`) and through `forge audit`/MCP via the unified
runtime.

Both entry points share a scope guard: they refuse to run downstream agents
when a repository has more `CONNECTED_ALIVE` modules than `--max-connected`
allows. The guard runs immediately after triage, so it bounds the rest of the
pipeline but not triage's own cost.

An MCP transport is now available in `forge/mcp_server.py`. It exposes
`audit_repository`, `get_coverage`, `get_findings`, `verify_seal`, and the
standalone `review_patch` tool. It changes **how** FORGE is invoked, not
**how** FORGE reasons.

### Hackathon build notes

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

Before submission, provide the actual Codex `/feedback` Session ID for the
build thread in the submission form. FORGE does not fabricate or hard-code
that external identifier.

### Codex build-session evidence

Known Codex sessions used during the build:

* `019f65d2-230f-71d2-ab70-e8195fb8fae0`
* `019f6693-c5fa-75e1-bc61-3c7af5ab6cc0`
* `019f6706-b195-7981-b21a-a01f98a6f785`
* _Three additional session IDs pending retrieval from screenshots._

### Running the MCP server

With the Python MCP SDK installed, start the stdio server with:

```bash
python3 -m forge.mcp_server
```

### Running the optional CRONOS MCP server

FORGE also vendors the private CRONOS runtime under `forge/cronos/`. Its MCP
surface is deliberately separate from the FORGE audit tools and is not started
by the normal server:

```bash
python3 -m forge.cronos_mcp_server
```

This optional server exposes CRONOS trace operations for an external agent.
The normal FORGE audit can use the same CRONOS implementation directly with
`Runtime(cronos_db=...)` or the MCP `audit_repository(..., cronos_db=...)` tool.
CRONOS records how FORGE executed; FORGE remains responsible for repository
discovery, governance skills, findings, sealing, and reports.

### Agent status: seventh agent is optional

FORGE currently has exactly seven agent modules:

| Agent | Automatic repository scan | Role |
|---|---:|---|
| Archaeologist | Yes | discovery, triage, deletion judgments |
| Bug Investigator | Yes | hypotheses and falsification |
| Security Auditor | Yes | AST security checks |
| Integrity Inspector | Yes | decision-path and serialization integrity |
| Report Composer | Yes, presentation only | HTML rendering |
| Patch Reviewer | No | review a requested unified diff |
| Recommendation Agent | No | propose bounded changes after the audit |

The seventh agent is deliberately post-audit and optional. Recommendations
are available only after contextual domain
hypotheses and executable skill contracts have run. The Recommendation Agent
consumes the sealed findings and metrics; it does not rescan, rewrite, or
change findings. It emits a suggestion with its evidence basis and regression
risk, and is never run by the normal audit. The current model-routing options
are configuration metadata only: the built-in agents do not call an LLM yet.

```python
recommendations = Runtime().recommend(
    "forge-run/verification-manifest.sealed.json",
    "forge-run/metrics.json",
)
```

The same operation is available as the optional MCP tool
`recommend_changes`.

## CRONOS as FORGE infrastructure

CRONOS and FORGE answer two different questions, and neither substitutes for
the other:

* **CRONOS asks: what did the system do?** — the event-level trace of the
  runtime itself: which stage ran, in what order, what it read, what it
  decided to skip.
* **FORGE asks: what did the system find?** — the sealed findings, discarded
  hypotheses, and coverage that make up the actual audit result.

One audits the process; the other audits the software. FORGE's sealed
`audit-trace.json` is where they meet: it is CRONOS's answer, cryptographically
bound to FORGE's answer, so a verifier can confirm not just *that* findings
weren't altered, but *how the run that produced them actually proceeded*.

CRONOS is a private project owned by the FORGE maintainer and is not a user
dependency or a public repository requirement. We use its strongest ideas
inside FORGE's runtime rather than exposing CRONOS as an agent:

* event-level tracing while the audit executes, not post-hoc narration;
* structured objective, discovery, hypothesis, evidence, discard, finding,
  artifact, and completion events;
* quality and limitation accounting derived from observed events;
* exact Fraction-based values where a ratio or confidence-like quantity is
  meaningful;
* tamper-evident binding of the trace to FORGE's sealed findings artifact;
* preservation of a partial trace when the runtime fails.

The current native implementation is `forge/tracing.py` plus the sealed
`audit-trace.json` artifact. It is adapted to FORGE's repository-audit domain:
CRONOS concepts such as recalls, tool calls, hypotheses, evidence, decisions,
quality, contradictions, and chain verification map to FORGE stages and
findings. The runtime remains the single execution engine; CLI, MCP, and
Python API all consume it.

The next CRONOS-powered layer is not another detector. It is a forensic
runtime store and trace-quality subsystem that can support cross-run history,
quality/diversity/contradiction checks, atomic persistence, and richer audit
trail metrics without changing detector logic. Until that exists, FORGE makes
no claim of an external append-only CRONOS database: its trace is persisted as
JSON and cryptographically bound into the sealed artifact.

---

## The agents

### Archaeologist (`forge/agents/archaeologist.py`)

Runs stack detection and module triage, then attaches a `deletion_judgments`
entry for every module classified `FOSSIL_HIGH_RISK` or `DEAD_WEIGHT`,
explaining in one sentence what deleting it would cost or save.

Classifies every module as `CONNECTED_ALIVE`, `FOSSIL_HIGH_RISK`,
`FOSSIL_LOW_RISK`, `DEAD_WEIGHT`, or `DUPLICATE`.

### Bug Investigator (`forge/agents/bug_investigator.py`)

Generates falsifiable hypotheses from live modules, then runs the module-3
adversarial verifier against them and ranks survivors by whether they fall
under an **AST-verified family** — a structural check that has an actual
implemented proof obligation, not just a keyword match:

* parser call without a real exception handler
* float comparison without `Decimal`/`Fraction`/`math.isclose`
* `eval`/`exec` on a non-constant argument
* `subprocess` call without a real `except` boundary

Anything outside those four families is capped at `PLAUSIBLE HYPOTHESIS` —
never promoted to a stronger claim without an executed check.

### Security Auditor (`forge/agents/security_auditor.py`)

Pure AST scanning, no network calls, no execution. Flags three families with
conservative, named benign criteria (see `DECISIONS.md`):

* **hardcoded-credential** — a non-empty, non-placeholder string literal
  assigned to a credential-shaped name, unless it comes from `os.getenv(...)`
* **unsafe-deserialization** — `pickle.load(s)`, `marshal.loads`, or
  `yaml.load` without `Loader=yaml.SafeLoader`
* **path-traversal** — a function parameter reaching `os.path.*` or `open()`
  without a visible `normpath`/`realpath` step first

### Integrity Inspector (`forge/agents/integrity_inspector.py`)

Also pure AST scanning. Flags two families:

* **decision-adjacent-float** — a `float(...)` call inside (or touching a
  variable named like) a function whose name or locals suggest a decision,
  score, verdict, classification, or gate
* **unversioned-serialization** — a `json`/`pickle` dump whose payload is not
  visibly a mapping containing `schema_version` or `version`

### Patch Reviewer (`forge/agents/patch_reviewer.py`)

Evaluates a unified diff against a stated intent: how much of the change sits
inside touched functions/classes versus outside any scope, and whether the
stated intent shows up in the names of the scopes it touched. Deliberately
excluded from the automatic repository scan — it reviews one proposed change,
not a whole tree.

### Report Composer (`forge/agents/report_composer.py`)

Wraps the self-contained HTML forensic report renderer: findings, discarded
hypotheses, clean modules, out-of-scope modules, a coverage table, and the
SHA-256 chain-of-custody block, all in one file with no external assets.

---

## Artifacts, not one giant JSON

A single `Runtime().audit()` run writes separate files rather than one
undifferentiated blob:

```
triage-manifest.json                every module's classification
hypotheses-manifest.json            candidates generated before verification
verification-manifest.json          findings + discarded, pre-seal
verification-manifest.sealed.json   the SHA-256 hash chain
coverage-report.json                discovered/analyzed/skipped, with reasons
skills-runtime.json                 governance-skill applicability + findings
metrics.json                        per-agent counts and examination summaries
audit-trace.json                    the CRONOS-derived event trace, sealed
forge-report.html                   the self-contained human-readable report
```

Splitting these on purpose, instead of nesting everything into one report
object, is what makes it possible to: reuse one stage's output without
recomputing the others; inspect a single stage in isolation when something
looks wrong; version each format independently as it evolves; and consume
any of it from MCP (`get_coverage`, `get_findings`, `verify_seal`, ...)
without parsing HTML.

---

## Sealing

Every completed `run_specialized_pipeline()` and `run_pipeline()` call
canonically serializes its `VerificationManifest` and seals it into a
SHA-256, append-only, genesis-anchored hash chain
(`forge/sealing.py::seal_manifest`).

The seal proves that sealed findings were not altered after sealing. It does
**not** prove the findings are correct, and it does not defend against a
full-access attacker forging a consistent replacement chain from scratch —
`DECISIONS.md` documents that boundary explicitly so it is never presented as
a stronger guarantee than it is.

---

## Engineering discipline

FORGE keeps the engineering methodologies in `skills-gpt/` as shared source
material and is migrating them into executable, contextual skill contracts.
The runtime must not apply every skill as a universal policy: a module's
domain hypothesis determines applicability. At present,
`validate-at-the-boundary` is the complete executable reference plugin; the
remaining catalog is not represented as active checks merely because its
documentation exists.

A governance skill is not a hardcoded `if float(): finding` check bolted onto
the core. It is a pipeline stage:

```
module
   │
   ▼
domain hypothesis            (infer_domains: machine_learning /
   │                          input_boundary / cryptographic, or none)
   ▼
applicable contracts         (each skill's own applicability() decides
   │                          APPLICABLE / NOT_APPLICABLE / UNDETERMINED)
   ▼
executable checks            (each applicable skill's evaluate())
   │
   ▼
findings
```

A new skill is a new directory under `forge/skills/` with a `manifest.json`
and a contract class — `forge/governance/runtime.py::load_skills()` discovers
it by walking `skills_root`, with no change to the core required. That is
the actual extensibility path today: a compliance, privacy, licensing, or
performance skill plugs in the same way `validate-at-the-boundary` did.
Adding a wholly new *specialized agent* (in the `Runtime._audit()` sense,
like Security Auditor) is a different, less pluggable path — it still means
touching the runtime — so this extensibility claim is scoped precisely to
governance skills, not to agents in general.

**Core reasoning** — Abductive Engineering · Red-Team Auditing · Secure by
Construction · Software Archaeology · Diagnosing Bugs · Codebase Health
Assessment · Reverse Engineering · Daubert-Defensible Writing · Claim
Provenance Discipline

**Determinism & integrity** — Deterministic Core · LLM Out of the Loop ·
Tamper-Evident Audit Chain · Atomic State Mutation · Versioned Schema
Evolution

**Safe editing** — Surgical Patcher · Audit Before Patch

**Data integrity** — Validate at the Boundary · Honest Degradation · SQL
Aggregation over Materialization

**Process discipline** — Git Discipline

---

## Evidence before confidence

FORGE reports what was actually inspected, using the real field names that
`run_specialized_pipeline()` writes to `coverage-report.json` and the report's
Quality Metrics table — not a rounded PR-deck summary:

```
files_discovered ................. every file under the audited root
files_analyzed .................... .py files that parsed cleanly
files_skipped ...................... files_discovered - files_analyzed
skipped_reasons
  excluded_by_policy ............... under a SKIP_DIRS entry (e.g. .venv)
  binary_or_unreadable .............. not valid UTF-8 text
  syntax_error ....................... .py file that failed ast.parse
  non_python_not_analyzed ........... readable, not excluded, not .py

coverage_ratio ..................... files_analyzed / files_discovered

audited_modules .................... modules read for hypothesis generation
findings (surviving) ............... entries in the sealed chain
discarded hypotheses ................ ruled out, kept with their reason
clean modules ........................ audited, zero surviving findings
out of scope .......................... not CONNECTED_ALIVE this run

chain_integrity ...................... OK / BROKEN (+ issues)
```

Every discovered file lands in exactly one bucket — `files_analyzed` or one
`skipped_reasons` entry — never both, never neither. That arithmetic
invariant is enforced by an adversarial regression test
(`tests/test_specialized_pipeline.py`), not just asserted in prose.

---

## Design principles

* Deterministic decision path
* No hidden reasoning promotion
* Evidence precedes conclusions
* Hypotheses remain auditable
* `ABSTAIN` is a valid outcome
* Honest degradation over false certainty
* Canonical, typed serialization
* Bit-for-bit reproducibility of the seal
* Minimal, read-only repository interaction
* Security-first engineering

---

## What FORGE does not do

FORGE intentionally does **not**:

* rewrite repositories automatically — every agent is read-only against the
  audited repository
* invent severity or epistemic labels — `epistemic_level` is drawn from the
  red-team-auditing vocabulary and never conflated with the `category` field
* hide discarded hypotheses — they are rendered in the report with their
  discard reason, not silently dropped
* convert an AST pattern match into a claim about runtime behavior it did not
  observe
* claim cryptographic guarantees beyond its documented threat model — the
  seal is tamper-evident, not tamper-proof, and says so
* replace human engineering judgment

---

## Development

Run all commands (`pytest`, `python3 -m forge`, and Git operations) from the
repository root: `/home/labestiadevigia/forge`. Running from a parent
directory can pick up unrelated files and produce misleading test or audit
results. This happened during the Kimi audit verification step.

Agent role contracts live in [`agents/README.md`](agents/README.md).

## Vision

FORGE treats repository governance as an engineering discipline rather than a
prompt engineering exercise.

Its goal is not to generate convincing explanations.

Its goal is to produce findings that survive independent scrutiny.

The differentiator is not the detector. "FORGE finds bugs with AI" describes
a script. What FORGE actually is: a governance runtime for reproducible
audits, where the detector is one replaceable layer among several — agents,
governance skills, a sealed trace, tiered reporting — each with its own
verifiable contract. A compliance, privacy, or licensing skill can be added
the same way `validate-at-the-boundary` was, without touching the core.
That is the difference between "an auditor" and a platform where the audits
themselves are traceable, reproducible, and governed by contracts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text and [NOTICE](NOTICE) for attribution.
