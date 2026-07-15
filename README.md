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

The objective is not simply finding more bugs.

The objective is producing findings that another engineer can independently
reproduce, challenge, or verify.

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

`forge.orchestrator.run_specialized_pipeline()` sequences six specialized,
single-responsibility agents. Five run automatically against a repository;
the sixth (Patch Reviewer) is deliberately kept outside that scan, because it
reviews a proposed diff, not a whole repository.

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

## Two orchestrator entry points

### `forge.orchestrator.run_pipeline()` — the original 5-stage pipeline

The module-1-through-5 pipeline (triage → hypothesis generation →
adversarial verification → sealing → reporting) as one dependency-ordered
call chain. Runnable via `python3 -m forge.orchestrator`.

### `forge.orchestrator.run_specialized_pipeline()` — the six-agent pipeline

Runs Archaeologist, Bug Investigator, Security Auditor and Integrity
Inspector, merges and seals their findings into a single `VerificationManifest`
(`schema_version="2.0"`), and renders one HTML report that also carries a
coverage breakdown. Called from Python today (`from forge.orchestrator import
run_specialized_pipeline`); it does not yet have its own CLI flag.

Both entry points share a scope guard: they refuse to run downstream agents
when a repository has more `CONNECTED_ALIVE` modules than `--max-connected`
allows. The guard runs immediately after triage, so it bounds the rest of the
pipeline but not triage's own cost.

An MCP transport is now available in `forge/mcp_server.py`. It exposes
`audit_repository`, `get_coverage`, `get_findings`, `verify_seal`, and the
standalone `review_patch` tool. It changes **how** FORGE is invoked, not
**how** FORGE reasons.

### Running the MCP server

With the Python MCP SDK installed, start the stdio server with:

```bash
python3 -m forge.mcp_server
```

---

## The six agents

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

FORGE embeds 20 engineering methodologies as versioned policy documents in
`skills-gpt/`, read in full before implementation and used as shared operating
context for every agent rather than inventing separate standards per agent.

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

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text and [NOTICE](NOTICE) for attribution.
