# The agents

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

## Agent status: seventh agent is optional

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
are available only after contextual domain hypotheses and executable skill
contracts have run. The Recommendation Agent consumes the sealed findings and
metrics; it does not rescan, rewrite, or change findings. It emits a
suggestion with its evidence basis and regression risk, and is never run by
the normal audit. The current model-routing options are configuration
metadata only: the built-in agents do not call an LLM yet.

```python
recommendations = Runtime().recommend(
    "forge-run/verification-manifest.sealed.json",
    "forge-run/metrics.json",
)
```

The same operation is available as the optional MCP tool
`recommend_changes`.

## Archaeologist (`forge/agents/archaeologist.py`)

Runs stack detection and module triage, then attaches a `deletion_judgments`
entry for every module classified `FOSSIL_HIGH_RISK` or `DEAD_WEIGHT`,
explaining in one sentence what deleting it would cost or save.

Classifies every module as `CONNECTED_ALIVE`, `FOSSIL_HIGH_RISK`,
`FOSSIL_LOW_RISK`, `DEAD_WEIGHT`, or `DUPLICATE`.

## Bug Investigator (`forge/agents/bug_investigator.py`)

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

## Security Auditor (`forge/agents/security_auditor.py`)

Pure AST scanning, no network calls, no execution. Flags four families with
conservative, named benign criteria (see `DECISIONS.md`):

* **hardcoded-credential** — a non-empty, non-placeholder string literal at a
  credential-shaped assignment target: a local name, attribute, string mapping
  key, or direct dict entry; or a non-empty, non-placeholder string literal
  passed as the *default* argument of `os.getenv(name, default)`, where `name`
  is credential-shaped. `os.getenv(...)` itself is a legitimate way to source
  a credential — the finding is specifically the hardcoded fallback that
  silently applies whenever the variable is unset, e.g.
  `os.getenv("ADMIN_PASSWORD", "admin123")`. Literal concatenation remains
  outside this direct-AST contract.
* **unsafe-deserialization** — `pickle.load(s)`, `marshal.loads`, or risky
  YAML loads (`load`, `unsafe_load`, `full_load`) without
  `Loader=yaml.SafeLoader`. The scanner resolves unshadowed module-level
  aliases and direct imports, but deliberately does not infer ambiguous local
  shadowing.
* **path-traversal** — a function parameter or locally propagated alias
  reaching `os.path.*` or `open()` through a direct expression, positional
  argument, or keyword argument without a visible composed
  `normpath`/`realpath`/`basename`/`resolve` barrier. `pathlib` sinks are not
  covered by this family yet. A parameter used solely as an external mapping
  key/index is not itself treated as the path value; a parameter used as the
  mapping container remains observable.
* **unverified-webhook** — a state-mutating route (`@app.post`/`put`/`patch`/
  `delete`) whose path is named like a webhook, with no FastAPI
  `Depends(...)` parameter and no signature/HMAC verification anywhere in
  its own body. Scoped to the "webhook" naming convention deliberately: a
  blanket "no `Depends()`" rule would flag intentionally public endpoints
  (checkout, cart) by design. A webhook claims to be an authoritative
  callback from an external system (a payment provider) and conventionally
  requires verifying the caller really is that system — accepting whatever
  the request body claims is a real, CRITICAL-impact bug (an unauthenticated
  caller can mark any order paid). Found the same way as
  `money-as-float`/`hardcoded-credential`: a stress-test audit of a
  quickly-built checkout service, where an AI coding agent's own narrative
  summary described this exact bug as if FORGE had verified it via
  execution — it had not; FORGE's sealed output at the time had no
  `bug_investigator` findings at all. Verified against the live code
  independently, then implemented as a real, sealed, evidence-backed check.

## Integrity Inspector (`forge/agents/integrity_inspector.py`)

Also pure AST scanning. Flags three families:

* **decision-adjacent-float** — a `float(...)` call whose value has a
  shallow data-flow path to a `return` statement, in *any* function. There is
  currently no name-based gate (no check for "decision"/"score"/"verdict" in
  the function or variable name) — the check is purely structural. The one
  exception is domain-based, not local to the function: a module inferred as
  `machine_learning` by `forge/governance/runtime.py::infer_domains()` (an
  import of `torch`/`tensorflow`/`sklearn`/`numpy`/`pandas`) is excluded,
  since ordinary numeric computation (model weights, predictions, physical
  quantities derived from signals) would otherwise be flagged identically to
  an actual governance verdict. The module is still examined for the other
  families below.
* **money-as-float** — a value that is float-typed *by provenance*, never by
  an explicit `float()` call, so `decision-adjacent-float`'s call-site
  tracing cannot see it at all: a SQLite `REAL` column declared with a
  money-shaped name (`price`, `cost`, `amount`, `total`, `subtotal`,
  `discount`, `fee`, `balance`, `charge`, `payment`) in a `CREATE TABLE`
  statement, or a `round(...)` call wrapping a `/` true division that
  touches a money-shaped name. Found via a stress-test audit of a
  quickly-built checkout service, where discounts computed as
  `product["price_cents"] * (1 - product["discount_percent"] / 100)` went
  completely undetected — the float never comes from a `float()` call, it
  comes from a SQLite `REAL` column and Python 3's `/` operator.
* **unversioned-serialization** — a `json`/`pickle` dump whose payload is not
  visibly a mapping containing a version key. That key is recognized
  structurally (`== "version"` or `.endswith("schema_version")`), not by an
  enumerated allowlist — found via a self-audit of `forge/sealing.py` itself,
  which false-flagged its own correctly-versioned `write_sealed_findings()`
  because the trusted-call allowlist had `seal_manifest` but not its sibling
  `seal_findings`, and because the codebase's ~10 `<domain>_schema_version`
  keys (`findings_jsonl_schema_version`, `metrics_schema_version`,
  `sharding_schema_version`, ...) were only ever partially enumerated by
  name — a new artifact type adds another one an exact-match set cannot see.
  A `json.dumps(...)` call is also trusted when it sits inside the body of a
  function named `seal_manifest`/`seal_findings`, or any `canonical_*`-named
  function (that function *is* the versioning primitive, not a caller of
  one — its own version marker lives one layer up, in whatever payload
  embeds its output) — found via self-audits of `forge/canonical.py`
  (`canonical_json`) and `forge/tiered_report.py`
  (`canonical_findings_bytes`). And presentation serialization — a JSON dump
  embedded as human-readable text, never a persisted artifact — is
  recognized both as f-string interpolation and as
  `html.escape(json.dumps(...))`, the report renderers' own convention.
  Version keys are also recognized any `_version` suffix, not just
  `_schema_version` (`trace_version` in `forge/multi_agent.py` follows the
  convention without the word "schema"). Finally, a local name assigned
  from a call to a *versioned-producer function* — one defined anywhere in
  the audited scope whose body returns a dict literal carrying a version
  key, resolved transitively through `return other_producer(...)` chains —
  is trusted the same as a literal dict assignment: `metrics =
  collect_metrics(...)` (`forge/runtime.py`) is versioned because
  `collect_metrics()` itself returns one, in a different file a literal
  check could never see across. A `json.dumps(...)` passed directly as one
  element of the parameter tuple in a `.execute(...)`/`.executemany(...)`
  call is also trusted — one column of an already-versioned SQL row (which
  typically carries its own version column, as `forge/cronos/store.py`'s
  `cronos_version` does), not a standalone JSON document. This is
  deliberately narrow — only a tuple passed *directly* as a call argument,
  never "any enclosing tuple" — because a broader version of this exact
  check silently suppressed 31 real findings elsewhere in the codebase,
  where a tuple happened to hold a genuine standalone JSON document (an
  `Evidence`/`Finding` field). Finally, a `json.dumps(...)` assigned to a
  local name that is only ever later passed to `hashlib.<algo>(...)` is
  trusted the same as `canonical_json`'s own internal dump — a
  content-fingerprint input, not a persisted document — found via a
  self-audit of `forge/agent_independence.py::_fingerprint()`, which splits
  the dump and the hash across two statements instead of one nested
  expression.

## Patch Reviewer (`forge/agents/patch_reviewer.py`)

Evaluates a unified diff against a stated intent: how much of the change sits
inside touched functions/classes versus outside any scope, and whether the
stated intent shows up in the names of the scopes it touched. Deliberately
excluded from the automatic repository scan — it reviews one proposed change,
not a whole tree.

## Report Composer (`forge/agents/report_composer.py`)

Wraps the self-contained HTML forensic report renderer: findings, discarded
hypotheses, clean modules, out-of-scope modules, a coverage table, and the
SHA-256 chain-of-custody block, all in one file with no external assets.
