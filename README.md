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

## The problem FORGE solves

Most repository reviews still begin with a prompt such as: “ChatGPT, find
bugs,” or “Codex, audit this repository.” The result is usually a list.

But a list rarely answers the questions a reviewer needs to trust it:

- Which parts of the repository were inspected?
- What remained outside the audit scope?
- Which hypotheses were discarded, and why?
- What evidence supports each finding?
- What could not be determined?
- Which agent performed each responsibility?
- Can the audit be reproduced exactly?

FORGE proposes a different answer. It is not a bug finder; it is a governed
audit runtime. It makes scope, evidence, discarded hypotheses, limitations,
role boundaries, and reproducible sealed artifacts part of the audit result
rather than optional commentary around a list of findings.

> FORGE behaves like a forensic engineering team.

```
Observe
   │
   ▼
Hypothesize
   │
   ▼
Falsify
   │
   ▼
Verify
   │
   ▼
Seal
```

The objective is not to produce more findings. It is to produce findings that
can be independently verified.

FORGE's normal audit path also keeps the decision mechanism out of the LLM
loop: discovery, AST parsing, structural detectors, hypothesis handling,
sealing, and report generation run as local deterministic code, so operational
cost scales with repository work, not with tokens sent to a model. Model
routing is explicit and recorded honestly rather than presented as evidence
that a model ran. See [`docs/model-routing.md`](docs/model-routing.md) for the
full configuration and a measured cost example.

---

## Proof: FORGE found a real bug in itself

Dogfooding isn't a slide, it's a run. Auditing the maintainer's own
`vigia-repo` (a repository FORGE had never seen) hung indefinitely instead of
completing. Root cause: an infinite loop in FORGE's own Integrity Inspector,
triggered by an entirely ordinary pattern — a variable reassigned with a
different `float()` call in each branch of an `if`/`else`. Fixed, with a
regression test; the same audit now completes in **~2.5 seconds instead of
hanging past a 280-second timeout**, and surfaces real findings in the
audited repository itself — including a probability returned as a raw
`float()` from a model prediction inside a function literally named
`calibrated_posterior()`.

Full writeup and all three run artifacts (JSON + HTML) in
[`annatchijova/forge-results`](https://github.com/annatchijova/forge-results#highlight-dogfooding-runs-that-found-a-real-forge-bug-2026-07-16).

---

## 30-second architecture

```
Repository
   │
   ▼
Archaeologist
   │
   ▼
Specialized agents  (Bug Investigator · Security Auditor · Integrity Inspector)
   │
   ▼
Evidence
   │
   ▼
Canonical Manifest
   │
   ▼
SHA-256 Seal
   │
   ▼
Reports
```

![FORGE verification report dashboard](docs/images/dashboard.png)

FORGE is not a single script that scans a repository and prints findings. It
is a small set of layers, each with one job, composed by one runtime:

| Layer | Lives in | Responsibility |
|---|---|---|
| **Core** | `forge/models.py`, `canonical.py`, `sealing.py`, `metrics.py`, `severity.py`, `io.py` | Typed data contracts, canonical serialization, SHA-256 sealing, run metrics |
| **Specialized agents** | `forge/agents/*.py` | Single-responsibility detectors — see [`docs/agents.md`](docs/agents.md) |
| **Governance skills** | `forge/governance/runtime.py`, `forge/skills/*` | Executable, versioned contracts loaded by domain applicability, not hardcoded into the core |
| **Harness** | `forge/harness/*.py` | Mines weaknesses from sealed runs, proposes bounded fixes, validates against the real test suite |
| **Tracing** | `forge/tracing.py`, `forge/cronos/*` | Event-level, tamper-evident record of what the runtime *did*, sealed alongside findings |
| **Orchestration** | `forge/runtime.py`, `orchestrator.py`, `mcp_server.py`, `cli.py` | The single execution engine and its thin frontends |
| **Reporting** | `forge/report.py`, `tiered_report.py` | Self-contained HTML at multiple detail tiers |

No agent reasons on another agent's behalf, and the orchestrator does not
delegate open-ended judgment to anything: each agent has a verifiable
responsibility and an explicit contract. Full agent-by-agent breakdown and
diagram in [`docs/agents.md`](docs/agents.md).

---

## Quick start

```text
Deterministic
Read-only
Reproducible
```

```bash
python3 -m forge audit /path/to/repository -o forge-run --max-connected 100
```

or from Python:

```python
from forge import Runtime
result = Runtime().audit("/path/to/repository", "forge-run")
```

Every audit produces a full evidence package in the output directory —
findings, discarded hypotheses, coverage report, sealed manifest, and a
self-contained HTML report.

Supports:

* CLI
* Python API
* MCP (see [`docs/mcp.md`](docs/mcp.md))
* The backward-compatible orchestrator entry point

Full frontend reference, large-repository demo mode, and the reproducible
benchmark corpus command are in [`docs/runtime.md`](docs/runtime.md).

Outputs:

* Interactive HTML report
* JSON artifacts (triage, hypotheses, findings, coverage, metrics, trace)
* SHA-256 sealed verification manifest

### Which report should I use?

An audit writes one evidence set and several views over it. The views do not
recompute findings; choose the one that matches the reader and the question.

| Open this | Use it for |
|---|---|
| `forge-report.html` | The interactive dashboard: best first view for a demo, a broad review, or a reader new to FORGE. |
| `forge-report-summary.html` | A fast, shareable status view when someone needs the result and boundaries without the full audit detail. |
| `forge-report-standard.html` | The normal daily-review report: overview, severity, grouped related findings, source locations, reproduction commands, discarded hypotheses, and coverage. |
| `forge-report-extended.html` | A forensic deep dive: use when reviewing reasoning chains, governance contracts, and the audit trace. |
| `verification-manifest.sealed.json` | Machine-readable evidence for MCP, automation, or independent verification — not the first file a human reviewer should open. |

For an everyday engineering workflow, start with **standard**. Use the
interactive dashboard to orient a new reviewer, and use **extended** only
when the evidence needs to be examined in depth.

Details on why artifacts are split rather than nested into one blob, and on
what the seal does and does not prove, in [`docs/artifacts.md`](docs/artifacts.md).

Historical audit and benchmark runs — including full findings, discarded
hypotheses, and known false positives — are kept out of this checkout and
published at
[`annatchijova/forge-results`](https://github.com/annatchijova/forge-results)
so anyone can browse past evidence without cloning large run artifacts.

---

## Why is FORGE different?

| Traditional AI auditor | FORGE |
|---|---|
| Pattern matching | Evidence-backed findings |
| Hidden reasoning | Explicit reasoning stages |
| Monolithic report | Typed forensic artifacts |
| Confidence score | Evidence boundaries |
| Opaque execution | Deterministic runtime |
| Trust the AI | Verify the evidence |

---

## Engineering philosophy

FORGE follows an abductive engineering workflow:

> Observation → Abduction → Deduction → Induction.

Evidence stays separate from inference throughout the pipeline; every finding
carries an explicit epistemic level (CODE FACT, PLAUSIBLE HYPOTHESIS, CONFIRMED
BY INDUCTION, FALSIFIED) that is never conflated with severity. Full vocabulary
and design principles in [`docs/philosophy.md`](docs/philosophy.md).

Governance policies (security, determinism, provenance, and more) are
implemented as executable, versioned skills loaded by domain applicability,
not hardcoded into the core. See [`docs/skills.md`](docs/skills.md).

Runtime tracing is powered by an internal CRONOS engine — see
[`docs/cronos.md`](docs/cronos.md).

---

## ABSTAIN: a feature, not a failure

FORGE never turns an incomplete audit into a clean bill of health. The global
audit disposition is deterministic and separate from the findings themselves:

| Disposition | Meaning | Next action |
|---|---|---|
| `COMPLETE_NO_FINDINGS` | Declared source scope was verified and no finding survived | No action within that scope |
| `COMPLETE_WITH_FINDINGS` | Declared source scope was verified and findings survived | Review the evidence |
| `ABSTAIN_INSUFFICIENT_SCOPE` | Source files were skipped, unreadable, syntactically invalid, outside scope, or in an unsupported language | Complete the scope and rerun |
| `ABSTAIN_UNDETERMINED` | Independent evidence paths contradict each other | Resolve the contradiction and rerun |
| `ABSTAIN_DEGRADED` | A specialized agent was unavailable but partial evidence was preserved | Restore the agent and rerun |
| `ABSTAIN_UNATTESTED_EXTERNAL` | External findings were preserved but FORGE cannot attest their analytical provenance | Review and explicitly operator-attest the external layer before relying on it as an audit result |

`ABSTAIN` does not erase findings. It says that FORGE refuses to generalize
from the inspected portion to the repository as a whole. A sealed report
proves artifact integrity; it does not prove complete coverage or analytical
correctness. In a multi-agent closeout, assembly attestation and each layer's
analytical provenance are separate claims: an attested canonical artifact can
still contain an explicitly `UNATTESTED` external layer and must abstain. See
[`docs/seal-authentication.md`](docs/seal-authentication.md) and
[`docs/vigia-inspired-governance.md`](docs/vigia-inspired-governance.md)
for the design rationale and [`DECISIONS.md`](DECISIONS.md) for the contract.

---

## What FORGE does not do

FORGE intentionally does **not**:

* rewrite repositories automatically — every agent is read-only against the
  audited repository
* invent severity or epistemic labels — `epistemic_level` is drawn from a
  fixed vocabulary and never conflated with the `category` field
* hide discarded hypotheses — they are rendered in the report with their
  discard reason, not silently dropped
* convert an AST pattern match into a claim about runtime behavior it did not
  observe
* claim cryptographic guarantees beyond its documented threat model — the
  seal is tamper-evident, not tamper-proof, and says so
* replace human engineering judgment

---

## Documentation

**Architecture**
* [`docs/runtime.md`](docs/runtime.md) — frontends, demo mode, benchmark corpus
* [`docs/agents.md`](docs/agents.md) — full agent-by-agent breakdown

**Evidence**
* [`docs/artifacts.md`](docs/artifacts.md) — output artifacts and sealing
* [`docs/seal-authentication.md`](docs/seal-authentication.md) — optional HMAC authentication for sealed artifacts and key handling
* [`docs/model-routing.md`](docs/model-routing.md) — model routing and the measured cost advantage

**Governance**
* [`docs/skills.md`](docs/skills.md) — governance skill catalog and extensibility
* [`docs/cronos.md`](docs/cronos.md) — the internal CRONOS tracing engine
* [`docs/philosophy.md`](docs/philosophy.md) — the Peircean reasoning loop and design principles

**Build**
* [`docs/mcp.md`](docs/mcp.md) — MCP tools and Claude Code integration
* [`docs/hackathon.md`](docs/hackathon.md) — build notes and Codex session evidence
* [`docs/technical-companion.html`](docs/technical-companion.html) — bilingual interactive technical companion for reviewers

**Reference**
* [`DECISIONS.md`](DECISIONS.md) — recorded architectural decisions and their boundaries
* [`agents/README.md`](agents/README.md) — agent role contracts
* [`annatchijova/forge-results`](https://github.com/annatchijova/forge-results) — historical audit/benchmark runs, findings, and false positives

Run all commands (`pytest`, `python3 -m forge`, and Git operations) from the
repository root: `/home/labestiadevigia/forge`. Running from a parent
directory can pick up unrelated files and produce misleading test or audit
results.

---

## Vision

> FORGE is not an AI auditor.
>
> It is a governance runtime for reproducible software audits.

The differentiator is not the detector. "FORGE finds bugs with AI" describes
a script. What FORGE actually is: a governance runtime for reproducible
audits, where the detector is one replaceable layer among several — agents,
governance skills, a sealed trace, tiered reporting — each with its own
verifiable contract. That is the difference between "an auditor" and a
platform where the audits themselves are traceable, reproducible, and
governed by contracts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text and [NOTICE](NOTICE) for attribution.
