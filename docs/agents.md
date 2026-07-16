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

Pure AST scanning, no network calls, no execution. Flags three families with
conservative, named benign criteria (see `DECISIONS.md`):

* **hardcoded-credential** — a non-empty, non-placeholder string literal
  assigned to a credential-shaped name, unless it comes from `os.getenv(...)`
* **unsafe-deserialization** — `pickle.load(s)`, `marshal.loads`, or
  `yaml.load` without `Loader=yaml.SafeLoader`
* **path-traversal** — a function parameter reaching `os.path.*` or `open()`
  without a visible `normpath`/`realpath` step first

## Integrity Inspector (`forge/agents/integrity_inspector.py`)

Also pure AST scanning. Flags two families:

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
  family below.
* **unversioned-serialization** — a `json`/`pickle` dump whose payload is not
  visibly a mapping containing `schema_version` or `version`

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
