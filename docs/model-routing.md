# Model routing and the cost advantage

## Explicit, shared model routing

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
source coverage: <analyzed>/<eligible source>; discovery accounting: <analyzed>/<discovered>
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
