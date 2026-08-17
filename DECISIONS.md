# FORGE Decisions and Work Record

## Project identity

FORGE (Forensic Repository Governance Engine) is being built for the OpenAI Build Week Challenge, Developer Tools track. The implementation and this record identify the collaborating model as **GPT-5.6 Luna**.

## Methodology adopted

Before implementation, every file in `skills-gpt/` was read. The design follows the supplied abductive-engineering, diagnosing-bugs, codebase-health-assessment, red-team-auditing, daubert-defensible-writing, deterministic-core, tamper-evident-audit-chain, software-archaeology, claim-provenance, honest-degradation, validation-at-the-boundary, Git-discipline, and related skills.

## Work completed

1. Proposed a modular project layout separating detector, triage, evidence, models, sealing, reporting, CLI, tests, and documentation.
2. Implemented module 1, stack detection and triage, in `forge/detector/stack.py`.
3. Added strict serializable models for stack fingerprints, evidence, module records, and the versioned `TriageManifest`.
4. Added confidence-scored language and configuration detection, caller/import search, duplicate-content detection, Git temporal evidence when available, and the five required health classifications.
5. Added multi-stack tests for Python and JavaScript fixtures.
6. Published module 1 to `https://github.com/annatchijova/forge.git` in commit `30143c1`.
7. Consolidated the working directory into a real clone of that remote, verified the clean status and matching history, created the `post-module1` restore tag, and removed the temporary `/tmp/forge-remote` checkout.
8. Implemented module 2, abductive hypothesis generation, in `forge/hypotheses.py`.
9. Added the required `Hypothesis` and `HypothesesManifest` schemas. Hypotheses require a module path, rank, description, source line(s), and non-empty executable falsification test at construction time.
10. Enforced read-before-reasoning: generation reads each live `CONNECTED_ALIVE` source file before constructing candidates. Fossils, dead weight, duplicates, and other non-live modules are not processed.
11. Added a boring-module fixture proving that the generator does not invent hypotheses when no risk signal is present.

## Deliberate boundaries

- Module 2 generates ranked candidates only. It does not execute or verify them; that belongs to module 3.
- The current caller graph is lexical and conservative. Dynamic imports, reflection, generated code, and framework dispatch remain explicit limitations.
- A clean Git status and matching commit establish repository alignment, not correctness of the audit logic.
- Hash sealing and HTML reporting remain later modules; no claim of tamper-evidence is made yet.

## Module 3 call-selection limitation

`_call_at` uses the function name extracted from the hypothesis description when
the expected backtick-quoted call format is present. If extraction fails, it
falls back to the first AST call on the line. This is deterministic but can be
an arbitrary structural choice for nested calls such as `foo(bar())`; the code
comment and regression test make this limitation explicit.

## Module 4 sealing boundary

The verification findings are sealed with a typed, versioned canonical JSON
encoding and a SHA-256 genesis hash chain. The seal proves that findings were
not altered after sealing; it does not prove that findings are correct. A
full-access attacker who can rewrite the entire report can forge a consistent
replacement chain from scratch, so the seal is tamper-evident, not tamper-proof.
`reported_chain_length` is not a truncation defense: it can be edited to match
any truncated chain with zero additional cost. Real truncation detection requires
an external anchor to the chain's final hash, published elsewhere and out of the
attacker's reach; this module does not implement one. It must not be presented as
a security property in reports or the demo video.

## Safety and provenance

FORGE remains read-only against audited repositories. Manifests carry schema versions and module-path references so triage and hypotheses can be cross-checked. Hypotheses are not findings and must not be rendered as confirmed conclusions.

## Module 2 limitations (intentional scope boundaries)

1. Pattern matching is line-based regex, not AST. It misses import aliases, multi-line calls, and indirection through wrapper functions. This is deliberate for fast candidate generation, not an oversight.
2. The safe-context check (`try:` within N lines above) is a proximity heuristic, not a scope-accurate check. A nearby `try` can wrap unrelated code and create false negatives. Module 3 must not trust this heuristic; it independently re-verifies enclosure via AST parent-node inspection before downgrading or dismissing a hypothesis.

## Module 3 benign criteria (AST decisions)

These are structural proof obligations, not heuristics:

1. **Parser without handling.** A parser call is benign only when its `ast.Call` has an actual `ast.Try` ancestor and an `ast.ExceptHandler` catches a known parse exception (`json.JSONDecodeError`, `ValueError`, `yaml.YAMLError`, or an equivalent explicitly named parser exception). A bare `except Exception` is classified as **silenced**, not handled: it does not prove that malformed input is distinguished safely.
2. **Float comparison.** A comparison is benign when its operands are statically non-float exact types (`Decimal`/`Fraction` expressions), or when the surrounding expression is an explicit `math.isclose` call with a tolerance (`rel_tol` or `abs_tol`). Exact comparisons against `0.0` or `1.0` remain risk candidates; they may be legitimate edge checks, but legitimacy is not an AST proof of numerical safety.
3. **Eval/exec.** Dynamic evaluation is benign only when its argument is an `ast.Constant` string literal *and* that literal's text does not itself contain an OS-execution pattern (`os.system`, `subprocess.*`, `shutil.rmtree`, a nested `eval`/`exec`, etc. — see `_DANGEROUS_EVAL_CONTENT` in `forge/verification.py`). Variables, concatenations, attributes, and all other expressions remain findings because their provenance is not structurally constrained. A literal argument only proves *provenance* is fixed at read time (an attacker cannot inject a different string at runtime); it does not prove the literal's own content is safe to execute, so a literal that is itself an OS-command payload remains a finding regardless of provenance. (Fixed 2026-07-15: `eval('os.system("rm -rf /")')` was previously discarded as benign purely because the argument was a constant string.)
4. **Subprocess.** A subprocess call is benign only when its `ast.Call` has a real `ast.Try` ancestor with an explicit subprocess-related handler (`subprocess.SubprocessError`, `OSError`, or a named equivalent). A generic catch does not establish a safe boundary.

`VerificationManifest` must report these four families as `AST-verified`; any family without an implemented structural checker is explicitly `unverified — falls through to PLAUSIBLE HYPOTHESIS without structural check`.

## Shared skills and future orchestration

## Specialized agent benign criteria

The Security Auditor uses structural proof obligations. A hardcoded credential is
benign only when the value is empty, a documented placeholder, or comes from an
environment lookup rather than an `ast.Constant` string. Deserialization is
benign only for `yaml.load` with an explicit `Loader=yaml.SafeLoader`, or for a
trusted local file created in the same function before a `pickle.load`; this is
deliberately narrow. A path operation is benign only when the parameter is
normalized/resolved or validated against an explicit allow-list before use.
Comments and names alone never prove safety.

The Integrity Inspector treats `float()` in a decision-adjacent function or
variable scope as risky even when no comparison occurs. Serialization is benign
only when the dumped mapping visibly contains `schema_version` or `version`.
This is a structural versioning check, not a claim that the schema itself is
correct.

## TriageManifest schema_version bump (1.0 -> 1.1)

The Archaeologist agent adds `deletion_judgments: dict[str, str]` to
`TriageManifest`, with `default_factory=dict`. No loader in this codebase
reconstructs a `TriageManifest` from a persisted JSON file today — the only
disk consumer (`forge/report.py`) reads triage manifests as plain `dict` via
`.get(...)`, so the new field is safe for anything reading old triage.json
output. `schema_version` is bumped from `"1.0"` to `"1.1"` anyway
(`forge/detector/stack.py`) because the value is not decorative in this
pipeline: `forge/hypotheses.py` and `forge/verification.py` already chain it
forward as `triage_schema_version` / `hypotheses_schema_version` to mark
cross-stage compatibility. Bumping it now, before the Prompt 2 orchestrator
introduces real cross-agent manifest persistence, keeps that chain honest per
the same `versioned-schema-evolution` discipline the Integrity Inspector
enforces on other code.

The repository vendors the 20 shared policy documents from `skills-gpt/` under
`skills-gpt/`. They are the common context for future specialized agents and an
orchestrator. The current implementation does not claim that the orchestrator
or MCP exists yet.

The operating model follows the Peircean triad: abduction proposes candidate
explanations, deduction derives falsifiable consequences, and induction earns
bounded claims from repeated observations. This applies beyond simple static
code: repositories using floating point or ML must expose numerical precision,
model uncertainty, data provenance, boundary tests, and degradation behavior
rather than being forced into an inappropriate binary safety story.

## Self-harness scope

The self-harness is a scoped deterministic analogue applied to FORGE itself. It
mines signatures from sealed runs, proposes only predefined edits, and uses the
real regression suite as held-out validation. The name does not imply the
paper's full stochastic, LLM-proposer implementation.

### Hypothesis candidate cap

The historical `candidates[:5]` cap was removed on 2026-07-17. Every generated
candidate now reaches module 3 verification. Presentation may group repeated
causes, but it cannot silently remove candidates or change the sealed finding
set. See `docs/fp-fn-reduction-2026-07-17.md` for the corpus gate and its
regression coverage.

## FP/FN reduction and bounded induction (2026-07-17)

The precision corpus is exact at `(family, path, line)` granularity and gates
global precision/recall. Historical FP ledger cases are corpus regressions;
the Bug Investigator is measured alongside static agents. Severity is a
deterministic projection of independent epistemic, controllability and
exploitability axes, not a synonym for family.

The separate seeded recall corpus measures only families FORGE explicitly
models. Its `positive` fixtures are exact identity obligations, its
`benign_twin` fixtures are precision guards, and its `out_of_scope` fixtures
are recorded but excluded from the recall denominator. This prevents a clean
run from being misread as a claim that general logic, authorization,
concurrency, type, or resource-lifetime bugs were searched. The gate is at
least 0.90 recall per represented family and zero benign-twin hits; see
`docs/seeded-recall-corpus.md`.

## Codex session record and recall interpretation (2026-07-18)

The initial seeded recall result is intentionally classified as a **floor**,
not as family-wide coverage. The positive fixtures were derived from the
detector contracts and therefore exercise canonical shapes. A 1.0 result proves
that those contractual shapes emit their expected exact identities; it does
not prove that realistic variants in neglected repositories are recognized.
The session record is preserved in `docs/codex-session-2026-07-18.md`.

The next measurement layer is a variants corpus. Misses such as a tainted
`open(user_path + suffix)`, a one-hop alias before `open`, a subscript target
holding a credential, or a non-literal `eval` are recorded as recall gaps and
backlog items. They must not be rewritten into canonical fixtures merely to
retain a green gate. This distinction is the same epistemic discipline used
for H1: a passing integrity check is not proof of analytical provenance, and a
passing canonical recall case is not proof of broad bug-class coverage.

Before variants, the out-of-scope safeguard must be checked at the rendered
report boundary. A real report over an out-of-scope fixture may say
`COMPLETE_NO_FINDINGS` only with the declared-scope qualifier; it must never
say or imply “no bugs.” The runner's `coverage_statement` is an intermediate
assertion, not a substitute for testing report language.

This pause records Codex's role as implementer, experimenter, and recorder,
not as an authority that can certify repository correctness. Every resulting
claim remains tied to a fixture, detector output, disposition, and commit.

### Variant corpus scope boundaries (2026-07-18)

The first variants baseline is intentionally below the canonical floor. After
auditing the mechanism behind surprising hits, it initially recorded 12
detected forms out of 36 variants. The first closure lot then raised that
measurement to 23/36 without changing the canonical 29/29 floor or producing
a benign-twin hit. Its import-alias, credential-target, and local path-flow
mechanisms are recorded in `docs/recall-gap-closure-lot-1.md`; every remaining
non-boundary miss stays in `tests/corpus/recall-variants-baseline.json`. Those
misses are recall backlog, not failures to hide or reasons to weaken the
canonical gate.

Two variants are explicit scope boundaries at this point: a credential formed
by concatenating literals (`"ab" + "cd"`) and an indirect evaluator invoked
through `getattr(obj, "eval")(value)`. Supporting those shapes requires an
obfuscation/indirection policy beyond the current direct-AST contracts and may
increase false positives. They remain measured, but do not enter the
close-gap ledger unless a future scope decision changes them. The remaining
MISS and `undecided` entries are visible in the variants baseline; they were
not reclassified away. The runner also records raw identity hits that fail a
declared mechanism check as `incidental_hit`, so an unrelated generic detector
path cannot inflate a variant's coverage claim.

Induction supports parser, eval/exec, subprocess, float-threshold and SQL
injection harnesses
inside a spawned, resource-limited worker. The worker blocks network, actual
process creation and writes outside its temporary directory before importing
target code. This is defense in depth, **not** a kernel-grade sandbox, and a
confirmation means only the stated harness behavior reproduced. Unsupported
or incompatible shapes remain `UNDETERMINED`.

JavaScript/TypeScript remains a bounded lexical scan. Coverage reports
language-level analyzed/abstained counts so this limitation is visible rather
than silently clean; unresolved multiline filesystem expressions are emitted
as explicit pending-verification observations. Cross-run comparison is scope-bound, and multi-agent
closeout requires an exact A-D-I cycle per hypothesis ID plus a shared
canonical finding-set digest across closeout artifacts.

## Executable skill runtime boundary

Skills are executable, versioned contracts loaded from local plugin manifests.
FORGE's core owns discovery, read-only context, applicability recording, typed
evidence, sealing, and reporting; a skill owns its domain-specific methodology.
Domain classification is an evidence-backed hypothesis per module, not a
repository-wide fact, and `UNDETERMINED` is retained when evidence cannot
justify applicability. `validate-at-the-boundary` remains the reference
contract. On 2026-07-17, five Class-A structural obligations were migrated
into executable plugins: `honest-degradation`, `deterministic-core`,
`atomic-state-mutation`, `sql-aggregation-not-materialization`, and
`tamper-evident-audit-chain`. Each has source-linked manifest provenance,
conservative applicability, explicit FP guards and positive/negative corpus
cases. Their findings use `PROTOCOL_GAP`, never `CONFIRMED BY INDUCTION`: a
structural observation is not a runtime proof.

The protocol ledger now receives the native `SkillRun`: executable statuses
are `APPLIED`, `NOT_APPLICABLE`, `UNDETERMINED`, or `ERROR` with evidence for
every applied claim. Markdown-only entries remain `LOADED_ONLY`. Process
disciplines are intentionally `PROCESS_LEVEL`, not falsely represented as a
per-module scan; their future contract will evaluate audit-run artifacts.
The external-agent validator rejects an `APPLIED` executable claim that
contradicts a native all-`NOT_APPLICABLE` result for the same scope.

## Runtime audit trail

FORGE now records a structured runtime trace analogous to CRONOS: events for
discovery, classification, coverage, domain hypotheses, skill applicability,
contract execution, hypotheses, discards, findings, metrics, artifacts, and
completion are persisted and embedded in the sealed artifact. The canonical
trace hash is verified with the findings chain. On failure, a partial
`audit-trace.json` with `run_failed` is retained; there is no claim of an
external append-only database or external final-hash anchor yet.

Metric interpretation is explicit. `contract_coverage` counts applicability
observations only for executable skill plugins loaded in that run; it is not
coverage of the larger documented `skills-gpt/` catalog. `evidence_completeness`
will require an obligation ledger mapping each contract obligation to a
satisfied or missing Evidence item. `verification_coverage` will require a
ledger of planned checks, executed checks, skipped checks, and skip reasons.
Until those ledgers exist, both remain `null` by design. Finding
reproducibility is separately testable through the canonical `finding_digest`;
it does not imply that timestamps, runtime duration, or the full trace bytes
are deterministic.

**Threat model — in-process plugin execution (documented, not sandboxed).**
`forge/governance/runtime.py::load_skills()` loads a skill's `entrypoint.py`
via `importlib.util.spec_from_file_location(...)` and
`spec.loader.exec_module(module)`. This runs the plugin's Python code inside
the FORGE process with FORGE's own privileges — there is no signature check,
hash pinning, or sandboxing. A compromised or malicious skill file has full
access to the FORGE process, not a restricted capability set. This is an
explicit, accepted scope boundary for the hackathon timeline, not an
oversight: **skills must only be loaded from directories controlled by the
FORGE operator** (the default is `forge/skills/`, versioned in this repo;
`skills_root` in `load_skills()`/`run_skills()` must never be pointed at an
untrusted or user-supplied path). If skill plugins are ever sourced from
outside the operator's own repository (a marketplace, a URL, a user upload),
this boundary must be revisited before that lands — options in order of
effort: (1) require a signed manifest with a hash pinned against a trusted
list before `exec_module()` runs, (2) execute the skill in a subprocess with
a restricted capability set, accepting the added latency. Neither is
implemented today. `run_skills()` does catch and record per-skill exceptions
(see below) so a *crashing* skill degrades gracefully — that is a reliability
boundary, not a security boundary, and does not mitigate this threat model.

### Self-harness mining coverage limitation

Self-harness weakness mining currently observes only
`bug_investigator`'s structured discarded-hypothesis records. The
`security_auditor` and `integrity_inspector` do not yet emit equivalent
"examined, ruled benign" records. Therefore the harness cannot learn from
their false-positive-avoidance patterns or benign safe-context decisions. A
synthetic regression test confirms that three safe Security Auditor runs
produce zero mining clusters; this is an explicit coverage gap, not evidence
that those agents had no examinable cases.

### `examined_clean` conflated two different depths of scrutiny (fixed 2026-07-15)

`bug_investigator`'s per-module `examinations` status used to label a module
`examined_clean` in two structurally different cases: (1) no hypothesis was
generated at all because no risk keyword matched anywhere in the module, and
(2) a hypothesis was generated, then discarded during module 3's adversarial
verification because an AST proof established the pattern was benign. Case 2
involved active scrutiny and a structural proof of safety; case 1 involved no
scrutiny beyond a keyword miss — conflating them understated how much
scrutiny a "clean" module actually got, the same distinction
`daubert-defensible-writing` requires elsewhere in this project.

Fixed in `forge/orchestrator.py::run_specialized_pipeline` by splitting the
status into `no_hypothesis_generated` (module path absent from
`bug.manifest.hypotheses`) and `hypothesis_discarded_benign` (module path
present there but not in the surviving findings), the same way
`examined_with_findings` / `excluded_by_scope` were already distinct.
`security_auditor` and `integrity_inspector` were never ambiguous here: their
`examined_clean` always meant an AST walk ran and found no match.

### `_caller_counts()` O(n^2) scan fixed (2026-07-15)

`forge/detector/stack.py::_caller_counts()` used to concatenate every
discovered file's text into one string once, then run a fresh `re.findall()`
full-text scan over that entire blob *per module* in the caller loop —
`O(total_repo_text_size x number_of_modules)`. Confirmed empirically before
touching anything: a synthetic fixture showed `re.findall` call count scaling
exactly 1:1 with module count (10/30/60 files -> 10/30/60 calls), with wall
time growing accordingly since the scanned text also grows with repo size.
This is why a ~484-file repository like VIGIA could be slow even after the
git-log batching fix.

Fixed by replacing the per-module loop with a single combined pass
(`_reference_tallies()`): one scan collects every `(?:import|from|require|use)`
line-tail via `finditer`, and for each such tail, tallies whichever known
module stems appear in it. Total regex work no longer scales with the number
of modules — only with total text size, once. `re.escape`'d stems are
still matched via `\b...\b` word boundaries against **line-scoped tails**
(`.` does not match `\n`, so behavior can't cross a line boundary), and only
the *distinct* stems present in each tail are tallied once, which reproduces
the old per-stem `re.findall(...).*\bstem\b` semantics for every case that
occurs in real code. Verified with parity tests comparing old vs. new output
on cross-import, duplicate-stem-in-different-directories, and multi-language
fixtures (byte-identical `(caller_count, import_count)` per module) plus a
scan-count regression test. The only theoretical divergence from the old
algorithm is an unreachable-in-practice edge case (the *same* stem name
repeated after a *second* keyword occurrence later on the *same physical
line*) that no real code in this repo's fixtures or corpus exercises; the
lexical/conservative caller-graph limitation already documented above still
applies unchanged.

### `run_skills()` did not isolate a failing skill (fixed 2026-07-15)

`run_skills()` called each loaded skill's `applicability()`/`evaluate()`
directly inside the per-module loop with no exception handling: a bug or
crash in any single skill (a missing file, a malformed AST assumption, an
unhandled edge case in third-party-style plugin code) raised out of
`run_skills()` and killed the entire governance run for every other module
and every other skill, not just the one that failed. Fixed by wrapping each
skill's evaluation in a `try/except Exception`: a failing skill now records
`"ERROR"` in `applicability[module.path][skill.contract.name]` and appends a
`"Skill <name> failed on <module>: <exc>"` entry to `SkillRun.limitations`,
so the failure is visible and attributed rather than either silently
swallowed or fatal to the run. This is a reliability boundary only — it does
not change the in-process execution threat model documented above.

### Sealed finding-chain hashes were not reproducible across runs (fixed 2026-07-15)

`forge/sealing.py::seal_manifest()` folded `trace_hash` (a SHA-256 of the
`audit_trace` payload, which contains a fresh `uuid4()` `run_id` and a
wall-clock `started_at` timestamp) into the per-finding chain hash payload
alongside `{index, finding}`. Confirmed empirically: running `Runtime().audit()`
twice on the identical repository produced *different* `chain[].hash` values
for the identical findings, purely because `run_id`/`started_at` differed
between runs. This is exactly the class of leak `deterministic-core` names
explicitly ("an unpinned timestamp or RNG seed") and breaks the project's own
testable claim that a seal is reproducible from identical inputs.

Fixed by removing `trace_hash` from the digest payload entirely (both in
`seal_manifest()` and the matching recomputation in `verify_sealed()`); the
finding-chain hash is now derived only from `{index, finding}`, as it always
was before the audit-trace feature was added. This costs nothing: the trace
is still independently tamper-evident via `manifest.audit_trace_hash`
(a top-level field, verified against the stored `audit_trace` in
`verify_sealed()`), which was already sufficient to detect a
substituted/altered trace without needing to also bind every finding's hash
to it. A regression test (`test_finding_chain_hashes_are_reproducible_even_with_an_audit_trace`)
seals the same findings under two different synthetic traces and asserts the
chain hashes match.

This has no schema-version bump and no backward-compatibility shim: the
broken behavior had zero test coverage and was added very recently (the same
work session that introduced `audit_trace`), so there is no prior sealed
artifact format to stay compatible with.

### `load_skills()` skips a broken plugin without recording why (known limitation)

`load_skills()`'s `except (...): continue` (see the in-process plugin threat
model note above) silently drops a skill whose manifest/entrypoint/contract
failed to load - it does not appear in `SkillRun.applicability` or
`SkillRun.limitations`, unlike a skill that loads but fails during
`applicability()`/`evaluate()` (which *is* now recorded, see above). A
completely broken skill is therefore invisible rather than degraded-with-a-note.
Not fixed here: `load_skills()`'s return type (`tuple[LoadedSkill, ...]`) would
need to change to also carry skipped-skill diagnostics, which touches every
caller (`Runtime.list_available_skills`, `Runtime.run_skill`, `run_skills`).
Left as a documented gap rather than a silent one; the fix is to return
`(loaded, skipped_with_reasons)` and fold `skipped_with_reasons` into
`SkillRun.limitations` in `run_skills()`.

## VIGÍA-inspired abstention and evidence boundaries

FORGE adopts VIGÍA's central fallback principle: inability to establish a
claim must never be serialized as a positive or clean result. `ABSTAIN` is a
first-class audit disposition, not an error path and not a synonym for “zero
findings”.

The disposition contract is implemented in `forge/disposition.py` and has six
states:

- `COMPLETE_NO_FINDINGS` — the declared source and detector scopes were
  verified and no modeled finding survived; it is not a whole-repository
  cleanliness certificate;
- `COMPLETE_WITH_FINDINGS` — the declared source scope was verified and one or
  more findings survived;
- `ABSTAIN_INSUFFICIENT_SCOPE` — source boundaries were skipped, unreadable,
  syntactically invalid, outside the connected audit scope, or represented by
  unsupported source languages;
- `ABSTAIN_UNDETERMINED` — governance applicability or cross-agent evidence
  interpretation could not be resolved;
- `ABSTAIN_DEGRADED` — a specialized agent was unavailable, while the
  remaining agents' evidence was preserved.
- `ABSTAIN_UNATTESTED_EXTERNAL` — external findings were preserved, but FORGE
  cannot attest their analytical provenance.

This is deliberately non-destructive. Findings, discarded hypotheses, skipped
paths, contradictions, and limitations remain available for review even when
the global disposition abstains. In particular:

1. A seal proves artifact integrity, not source completeness or correctness.
2. `non_python_not_analyzed` is an intentional engine boundary, but recognized
   unsupported source languages are promoted to an actionable insufficient
   scope boundary.
3. A contradiction has precedence over a clean conclusion and produces
   `ABSTAIN_UNDETERMINED` with `CONTRADICTORY_EVIDENCE`.
4. A failed Security or Integrity agent produces `ABSTAIN_DEGRADED`, never a
   zero-finding success.
5. Every abstention carries an evidence boundary and a required next action.

## H1 provenance closure (2026-07-18)

H1 showed that a canonical multi-agent seal could contain raw external
`findings.json` content while a consumer saw only a successful hash-chain
verification. The chain proved post-assembly integrity, but the presentation
could be read as if it also proved that the external content came from a real
FORGE audit.

The fix separates the two claims. `FORGE_ATTESTATION_KEY` provides a persistent
runtime assembly attestation, surfaced by `verify_sealed()` as
`attestation_status`; the process-local fallback is explicitly
`EPHEMERAL_UNVERIFIABLE`. The finalizer never auto-attests external findings.
It labels them `UNATTESTED`, preserves them for review, and returns
`ABSTAIN_UNATTESTED_EXTERNAL`. A human operator may explicitly attest an
external findings envelope with the configured key, changing that layer to
`OPERATOR_ATTESTED`; this is a deliberate act of review, not evidence that
Codex itself ran a native audit. `NOT_PRESENT`, `KEY_UNAVAILABLE`, and
`EPHEMERAL_UNVERIFIABLE` are visible evidence limits and do not masquerade as a
valid attestation; only `FAILED` makes the seal itself fail verification.

The same boundary is reflected in the self-assessment metrics. A qualitative
confidence boundary is reported instead of an invented numeric score. This
keeps the VIGÍA lesson intact while preserving FORGE's code-audit vocabulary.

## Honest degradation: logging is not structural degradation (2026-07-17)

The executable `honest-degradation` contract treats a handler that raises,
returns a named error, or records an explicit degraded/error state differently
from a handler that simply hides the degraded path. A VIGÍA-labelled specimen
showed a sharper boundary: catching an exception, logging "invalid item
ignored", and then `continue`-ing inside a loop can still produce a plausible
partial verdict. The log is diagnostic evidence for an operator, but it is not
machine-consumable degradation state for the caller.

FORGE therefore classifies `except ...: log; continue` as a protocol gap when
the handler does not raise or mark an explicit degraded/error flag. The benign
counterpart is a handler that logs and also propagates degraded state into the
returned result or surrounding control flow. This remains a narrow structural
subset: ordinary logged failures are not findings merely because they log.

The same rule applies to intra-function stage swallowing: if a caught
exception replaces a stage/component result such as `caie`, `timeline`,
`signal`, `artifact`, or `bundle` with `None`/empty/default and that name flows
to the returned result, the log is not enough. The handler must raise, emit an
`*_UNANALYZED`-style sentinel, append to an error/drop accumulator, set an
explicit skipped/degraded/error flag, or call an explicit marker such as
`mark_degraded`/`record_drop`. Optional scalar fields and cleanup in `finally`
remain outside this contract.

The default-return subset is deliberately gated by complete stage verb
segments (`to_signal`, `run_full`, `load_artifact`), not raw string prefixes:
`token_count` and `runtime` are not stages merely because they begin with
`to`/`run`. Likewise, a parse sentinel exemption is based on a narrow named
exception (`SyntaxError`, JSON/Unicode decode errors, and equivalent parser
errors), never on naming a function `parse_*`. This controls false-positive
flooding while leaving unmodelled helper names as an explicit coverage limit.

Likewise, `log; return None` remains a degraded default return only when it
appears in a required stage/conversion helper or a stage-shaped try body. A
plain optional getter such as `get_nickname(...): return None` is not a finding
without additional evidence that the missing field is required.

## Source classification and coverage honesty (2026-07-17)

A Corvus/CRONOS stress test showed that decoding an arbitrary 8 KiB prefix as
UTF-8 can cut a valid multibyte character at the sample boundary. Treating that
decode error as a binary signal excluded valid authored source before AST
analysis. FORGE therefore uses the stable NUL-byte heuristic for
`binary_file`; a UTF-8 decode error after that point is reported separately as
`non_utf8_text`, and I/O failures as `unreadable_file`. Policy exclusions and
oversized files have their own coverage buckets.

This distinction is contractual: a source file must never be silently reduced
to binary scope because an arbitrary sample boundary split a valid character.
Every exclusion remains visible with a cause that tells a reviewer whether to
extend scope, repair access, or treat the file as genuine binary content.

The coverage headline is bounded by `eligible_source_files`, not every
filesystem object found below a root. `coverage_ratio` is analyzed built-in
source types divided by eligible built-in source types. `discovery_ratio`
retains analyzed/discovered arithmetic only as context; it may include
intentionally excluded VCS objects, images, documentation, and unsupported
languages and is never a source-coverage claim.

An I/O failure is likewise never evidence of binary content or file size:
binary and oversized predicates leave an inaccessible path for the reader to
report as `unreadable_file`.

## Corvus drip-feed boundary (2026-07-17)

The Corvus/CRONOS red team also demonstrated a drip-feed manipulation pattern:
one tactic per message stays below a per-message corroboration threshold even
when the sequence is persuasive as a whole. Repairing the UTF-8 scope bug lets
FORGE inspect the gate implementation, but it does not make this pattern a
detector false negative. The built-in analysis is per module and per AST; it
does not model temporal, cross-message state. That class is declared in
`UNMODELED_DEFECT_CLASSES` as **cross-message temporal and stateful behavioral
sequences**. It remains an external red-team finding and a scope boundary, not
a recall miss or an unearned claim that FORGE audited the behavioral invariant.

## Git ref auditing

`Runtime.audit_ref()` audits a branch, tag, or commit by resolving the ref with
`git rev-parse --verify` and extracting its committed tree with `git archive`
into an isolated temporary directory. It never performs checkout, reset, merge,
index updates, or writes to the audited repository. The trace records both the
requested ref and its resolved commit SHA before the audit is sealed.

`git archive` reads exactly the committed tree. Untracked files and uncommitted
working-tree changes are intentionally not included. This is correct for CI
and branch governance, where the audited unit is a committed ref, but it must
not be confused with auditing the caller's local working directory.

`Runtime.compare_refs()` audits base and head independently, then compares their
verified sealed manifests into `new`, `resolved`, and `unchanged` findings. It
also records the merge-base-derived changed file list and both resolved commit
SHAs. The two audit directories remain available under the comparison output
for independent verification.

## Proposal loops and authority boundaries

The optional proposal loop is a separate concern from the audit MCP. The audit
MCP produces the sealed forensic evidence; the loop consumes that evidence and
may propose or temporarily apply a patch, but it cannot edit the original
repository or alter a sealed manifest.

The loop uses a detached Git worktree for patch application and test execution.
Each iteration is bounded and re-audited by the normal FORGE runtime. Only the
re-audit can classify a finding as resolved. A proposal provider may be
`deterministic`, `human`, or an explicitly configured `llm` adapter. The
deterministic and human paths require no model credits. The current `llm`
provider abstains when no adapter is installed; it never pretends that a model
was called.

The state machine records `AUDITED`, `PATCH_PROPOSED`,
`PATCH_APPLIED_TEMPORARILY`, `TESTED`, `REAUDITED`, `CONVERGED`,
`STILL_PRESENT`, and explicit abstention/failure states. A model or human may
author a proposal; FORGE remains the judge.

## Multi-language analysis via declarative language packs

FORGE recognized ten languages during triage and analyzed two. Go, Rust, Java,
Ruby, C, C++, and C# were classified into module health classes and then never
inspected by any detector, so a Go repository could finish an audit with no
findings — a cleanliness that came entirely from having looked at nothing.

### Why lexical packs, and not a real parser

Adding a parser per language means adding `tree-sitter` or an equivalent: a
native dependency, a build step, and the end of the property this runtime is
built on — that the core audit path is local, read-only, stdlib-only, and needs
no API key or network. That price buys precision FORGE is not otherwise able to
claim anyway, because it has no induction harness for these languages and so
could not raise a parsed finding above an observation regardless.

A language is therefore described as data. `forge/languages/spec.py` declares
what a `LanguagePack` is: extensions, comment syntax, string-literal forms,
sink rules, sanitizers, and custom rules. `forge/languages/engine.py` owns the
one operation every pack needs — masking comments and string data out of source
while preserving line and column geometry — and the shared primitives built on
it. Adding a language is a specification, not an agent.

Masking is contractual, not incidental. It runs in a single pass with no
backtracking, so minified bundles and unterminated literals are ordinary input
rather than a denial-of-service vector against the audit. It preserves geometry,
so a reported line and column point at real positions. And it is per-language,
which is what makes Rust lifetimes, Go rune literals, nested block comments,
variable-width raw-string fences, and JavaScript regular-expression literals
safe: each of those would otherwise open a phantom string and silently blank the
remainder of a file, turning an unanalyzed file into a clean one.

Two exceptions to blanking are deliberate. String *delimiters* survive, because
a detector often needs to know an argument was a literal (`exec.Command("sh",
"-c", cmd)`) without seeing its text. JavaScript template *interpolations*
survive in full, because `${userInput}` reaching `readFile` is code flowing to a
sink, not inert data; that is what closed the `variant-web-template-path` gap.

### Analysis depth is reported, never implied

Findings now arrive at two depths, and a reader must not have to guess which
produced a given result. `ast` means a real parse tree, Python only, verifiable
structurally and reproducible by induction where a harness exists. `lexical`
means a masked-text scan with no scope, no type information, and no
reachability. Coverage reports depth per language; the disposition's language
scope statement declares which families were reachable in which language at
which depth. Every lexical finding is `NOT_ASSESSED` for exploitability, and
packs are not permitted to raise it.

### Coverage buckets separate three different facts

`non_python_not_analyzed` collapsed three unrelated situations into one list:
source in a language with no detector, source in a supported language that fell
outside the connected detector scope, and files that are not source at all. A
reviewer reading that bucket was shown a `README.md` and an unanalyzed Rust file
as the same kind of gap. They are now `unsupported_language_not_analyzed`,
`out_of_detector_scope`, and `non_source_not_analyzed`. Only the first is an
engine limit, and only it reaches the disposition's evidence boundary. The set of
unsupported languages is derived from the registry rather than restated, so
shipping a pack removes its language from the abstention automatically.

`eligible_source_files` — the coverage denominator — now counts every language
FORGE can analyze at any depth, not just Python and the web extensions.

### Agent boundary

`web_auditor` keeps its name, its JavaScript/TypeScript scope, and its recorded
precision and recall baselines; only its engine moved into the pack registry.
Renaming it to match the refactor would have meant rewriting the agent labels
inside `precision-baseline.json` and the recall corpus, which is editing the
audit record to suit the code. Go and Rust are covered by a new
`lexical_auditor` sharing the same engine and the same honesty constraints.

### Connectivity is resolved per language, not tallied

Triage classified non-Python modules by counting how often a file's *stem*
appeared on any import-looking line anywhere in the repository. That is wrong in
both directions and the errors are not symmetric noise: two files named
`config.ts` in different directories were indistinguishable, so an orphan
inherited its namesake's callers and was classified `CONNECTED_ALIVE`; an
`import store from "store"` credited a local `store.go`; a Python `import
frontend` credited `frontend.ts`; and a Rust file reachable only through a `mod`
declaration — the actual mechanism wiring a crate together — scored zero and was
reported as dead weight.

`forge/detector/imports.py` resolves each language as that language defines
reference. Go imports name a package directory, so an import credits every file
in it, anchored on the `go.mod` module path when present and falling back to an
unambiguous trailing match otherwise. Rust connectivity is the `mod` declaration
chain, plus `use crate::` paths. JavaScript and TypeScript resolve relative
specifiers only, with extension and `/index` resolution; bare specifiers are
packages and credit nothing.

Java, Ruby, C, C++, and C# keep the stem tally, and triage now states that
limitation in the manifest rather than letting an approximated count read as a
resolved one. Entry points are recognized per pack and read from `package.json`
and `Cargo.toml`, because an entry point has no importer by construction and
would otherwise be the one certainly-live file classified as dead weight.

### Recall gaps closed

`variant-web-template-path` and `variant-web-exec-file` were declared
`close_gap` misses and are now detected; the variant baseline moved from 30/39
to 32/39. The `.jsx`, `.tsx`, `.mjs`, and `.cjs` spellings were absent from
`LANG_EXT`, so those files were never triaged, never became `CONNECTED_ALIVE`,
and were therefore invisible to every detector rather than declared out of
scope. They are now recognized.

### A reserved-word constraint on finding text

`find_contradictions` treats the words `placeholder`, `fixture`, `test value`,
`test-only`, and `example` in any finding co-located with a credential finding
as an alternative explanation for that credential. A Go SQL finding initially
read "instead of placeholder binding", which made any module holding both
findings abstain the entire audit under `CONTRADICTORY_EVIDENCE` for a reason
nobody had asserted. Finding text must avoid those words; a test over every pack
enforces it.

## Sharded coverage: union the shard-scoped half, pin the repository snapshot

Sharding bounds detector attention on repositories with more than
`max_connected` live modules. Two defects in how its results were combined made
a sharded audit weaker than a single-shard one, and adding language packs made
both worse rather than better.

### Coverage aggregation compared what it should have unioned

The parent coverage was published only when every shard's snapshot was
byte-identical, and otherwise abstained with `ABSTAIN_INCONSISTENT_SHARD_SNAPSHOTS`.
But shard snapshots are not supposed to be identical. Parsing is repository-wide:
`_coverage` parses every Python file regardless of which shard is running, and
language and exclusion classification are decided by extension. Lexical analysis
is not: a Go, Rust or TypeScript file is scanned only by the shard whose
`CONNECTED_ALIVE` scope contains it and is `out_of_detector_scope` in every
other. Requiring identical snapshots therefore guaranteed a mismatch on any
repository containing lexically-scanned source, and collapsed *every* parent
count — `files_analyzed`, `coverage_ratio`, the entire language matrix — to
null. FORGE's own repository, which shards into three, reported no coverage at
all.

The two halves are now treated according to what they are. Repository-wide facts
must agree, and a disagreement still abstains, because it means the shards did
not audit the same tree. The shard-scoped half is unioned: the lexical agents run
once over the full connected set, which is exactly the union each shard
contributes a slice of, and one repository-wide snapshot is built from that.
Per-shard detector scope stays listed separately, so no reader can mistake a
union of scopes for a single shard's attention.

### Shards attested different trees

Shards run sequentially, and each shard's audit walked the filesystem itself. With
the output directory inside the audited repository — which is what the documented
`forge audit . -o forge-run` quick start produces — every shard after the first
discovered the artifacts its predecessors had just written. On a five-file
fixture, three shards discovered 5, 23 and 41 files and sealed three *different*
`repository_snapshot_sha256` values for one audit of one unchanged repository.

That is a seal-integrity problem, not a reporting one: a snapshot hash is an
attestation about the tree that was audited, and three conflicting attestations
for the same run cannot all be true. Discovery is now taken once, before the
first shard starts, and pinned for every shard through `discovery_override`. All
shards attest the repository as it stood when the audit began.

### Report rendering

The language matrix reached the HTML report as an escaped Python `dict`, which
made the report's single most important qualifier — whether a language was
parsed or merely scanned — effectively unreadable. It is a table now, sorted so
that depth reads as a hierarchy of evidence, with the per-language family list
kept in a collapsible block rather than dumped into the lede. The three
not-analysed buckets each carry the reason a reviewer would act on, so a
`README.md` no longer presents as the same kind of gap as an unanalysed Java
file.

## Auditing the language packs against benign code

The packs shipped with positive fixtures and benign twins written alongside the
detectors, which is exactly the corpus most likely to agree with them. Running
them instead over idiomatic Go and Rust written independently -- a config
loader, a bound query, a git invocation, a default-port parse -- surfaced four
false positives that the paired twins had not.

**A constructed bound parameter is not a constructed query.** In
`db.QueryRow("SELECT count(*) FROM e WHERE ts > $1", fmt.Sprintf("%s", since))`
the query is a constant and the formatting builds a *bound parameter* -- the
safe form. Scanning the whole call span reported it as injection. The rule now
inspects argument zero only.

**`execute` and `query` are not reserved for databases.**
`step.execute(format!("step-{}", step.id))` is ordinary domain code. A query
sink's first argument must now actually contain SQL, checked against the raw
text after the masked view has established the call is real code -- the same
discipline the credential rule already used.

**Parsing a compile-time constant cannot fail at runtime.**
`"8080".parse().unwrap()` and `let raw = "3"; raw.parse().expect(...)` were
reported as panicking parser boundaries. Idiomatic Rust is full of both, and
neither is actionable. A literal receiver, directly or through a
literal-only binding, is excluded; masking keeps the quotes while blanking their
contents, which is enough to tell a constant from a runtime value without
reading what the constant said.

All four fixes narrow the rules rather than suppress the families: the
concatenated-SQL form, `sqlx::query(&format!(...))`, and
`raw_header.parse().unwrap()` all still report. Each false positive is now a
regression test, and the benign service files are fixtures in their own right.

The one remaining Go finding on that corpus -- `exec.Command("git", "log", ...)`
reported as `subprocess` -- is deliberate and consistent with the JavaScript
pack reporting every `child_process.exec`. Process creation is a declared
boundary; only handing a constructed string to a shell is escalated to
`command-injection`.

## Java and C# packs, and what auditing them changed in the engine

Adding two languages cost two specifications and two benign-code audits, not
two agents. That is the return the language registry exists to pay, and it is
the first evidence that the abstraction holds.

Both are owned by `lexical_auditor`. Its former constant `SYSTEMS_PACKS` was
renamed `LEXICAL_AUDITOR_PACKS`: the split from `web_auditor` is by agent
ownership, and calling Java and C# "systems languages" would have been a
taxonomy claim the code does not need to make.

### What each pack can honestly see

Java (7 families) is the only pack with **file-scoped** rules, because that is
where its evidence lives. XXE is proven by an absence — no `setFeature`, no
secure processing anywhere in the compilation unit — and hardening is
conventionally written a few lines below the factory, not on it, so a
line-scoped check would report every correct usage. A script engine's `eval` is
treated as a data-to-code boundary only in a file that imports the scripting
API; every other `eval` in Java is someone's ordinary method.

C# (5 families) has the richest string syntax of any pack: verbatim strings
where a backslash is ordinary and a doubled quote is an escape, interpolated
strings whose substitutions are code, and both combined in either order
(`$@"…"` / `@$"…"`). All are declared longest-opener-first, and `StringRule`
gained `doubled_close_escapes` so `@"say ""hi"""` is not cut short at its own
escaped quote. Its `unsafe-deserialization` rule requires the file to name a
formatter that rebuilds arbitrary object graphs, because `Deserialize` is also
how every safe JSON library spells its entry point.

Their imports are **not** resolved. Java and C# are scanned at lexical depth but
their module connectivity still comes from the filename tally, and triage
declares that. Analysis depth and connectivity resolution are independent
claims, and the language matrix reports them in separate columns so neither is
read as implying the other.

### One false positive, and the engine change it forced

Auditing the two packs against idiomatic benign code produced a single finding:
`File.ReadAllText(target)` where `target = Path.Combine(root, ConfigName)`. It
exposed two defects, one shallow and one not.

The shallow one: `path` was a taint stem for both packs, and it matched the
`Path`/`Paths` *namespace* — the same collision the JavaScript pack had already
been taught to avoid. It is gone from both.

The real one: a variable was treated as suspicious because of what it was
*called*, never what was assigned to it. Every conventional destination-path
name — `target`, `filename`, `name` — was a traversal candidate the moment a
normalizer was not visible on the same line. `untainted_names` now clears any
assigned name whose expression shows nothing externally-shaped, through the
same fixed point the sanitizer set already used, so `target = Path.Combine(root,
ConfigName)` is clean while `target = Path.Combine(userInput, ConfigName)` is
not. Only *assigned* names can be cleared: a function parameter has no visible
origin and stays suspicious, which is the case the rule exists to preserve.

Java's deserialization pattern also matched both the construction and the read
of an `ObjectInputStream`, so one boundary produced two findings on one line at
different columns — which the runtime's deduplication, keyed partly on column,
could not collapse. The read is the boundary; the construction is its setup.

## Ruby and PHP packs, and the invariant they exposed

These two put nearly all their difficulty in the masker rather than the rules,
which is why adding them required three new engine capabilities rather than
just two specifications.

**Heredocs.** Ruby and PHP both keep SQL and shell text in heredocs. Without
support the body is read as code, which invents findings out of quoted data. A
pack now declares a heredoc opener whose `label` group names the terminator, and
the body runs to the first later line whose stripped text is that label.

**Code regions.** PHP is the only language here where a file is not code by
default: a template is HTML until `<?php` opens. `code_delimiters` blanks
everything outside a code region, so prose in the markup — including a
sink-shaped sentence in a paragraph — is never scanned.

**Simple in-string preservation.** `interpolation` handles the nesting-aware
brace form; PHP's bare `$name` needed a plain regex, so `StringRule.preserve`
was added. Both keep an interpolated query visible as a value reaching a sink
rather than as inert text.

### Two defects found by auditing, and one by testing

Ruby's `=begin`/`=end` block never matched. The opener is line-anchored, so the
pack declares it with a leading newline — but the masker skipped newlines before
trying block comments, so the scanner was never standing where the opener began.
Every such block was invisible and its prose was scanned as code; the benign
corpus produced two findings out of a comment saying what the code *used to* do.
The newline skip is gone, and `_block_opener` also matches a line-anchored
opener at offset zero, where a licence header has no preceding newline.

The SQL keyword guard added for the earlier false-positive pass turned out to
cost a true positive here. Rails' `.where("n = '#{param}'")` is a real injection,
but an ORM fragment method receives a *clause*, never a whole statement, so
demanding `SELECT` lost the finding while protecting nothing. `sql_findings`
grew `require_sql_keyword`, and Ruby splits raw sinks (generic names, keyword
required) from fragment methods (the name itself is the proof).

PHP's taint pattern captured the `$` sigil while assignment targets are recorded
without it, so the sanitized and untainted sets could never match a name up and
a provably-cleared path was still reported. Found by a test rather than by the
benign corpus, because the corpus happened to use a sink the pack does not model.

### The invariant

`index.php` finished the first end-to-end run in `out_of_detector_scope`: the
pack could read it, but `LANG_EXT` did not list `.php`, so triage never
classified it, it never became `CONNECTED_ALIVE`, and no detector could reach
it. That is the same latent defect `.tsx` had, and `.rake` and `.phtml` had it
too — a file that is *invisible* rather than declared out of scope, which is the
one outcome the coverage contract exists to prevent.

Anything a pack can analyse must therefore be triageable, and that is now
checked at import: registering a pack whose extensions triage cannot classify
raises rather than silently producing an unreachable language.

## Resolving connectivity for Java, C#, Ruby and PHP

Those four were scanned by a language pack while their module connectivity
still came from the repository-wide filename tally. Depth and connectivity are
independent claims, but leaving half of them approximated meant a detector's
scope was decided by a heuristic already documented as wrong in both directions.

Each resolver answers the question its language actually asks. A Java import
names a fully-qualified type, and a public type conventionally lives in the file
named after it inside its package directory, so the declared `package` plus the
filename resolves one exactly; a wildcard credits the package. A C# `using`
imports a *namespace* rather than a type, so it credits every file declaring it.
A PHP `use` resolves the same way through PSR-4, with literal `require` paths
resolved relative to the including file.

Two of them needed something imports alone cannot give.

**Same-scope siblings.** Java and C# reference a sibling type in the same
package or namespace with no import statement at all. An import-only resolver
would report every same-package collaborator as dead weight. Those are counted
by simple name — but bounded to the package, never repository-wide, because two
classes called `Config` in different packages are different classes and
crediting both is precisely the defect the stem tally had.

**Autoloaded constants.** A Rails application frequently contains no `require`
at all: a file is reached because something names the constant it defines. The
constant is derived from the filename and counted, and dropped entirely when two
files would claim the same one. A camelized constant is distinctive enough that
this is far tighter than a stem tally, and the ambiguity rule keeps it from
reintroducing the same error.

### Framework entry points

Testing the resolvers against realistic layouts surfaced a defect worse than the
one being fixed: **controllers were classified dead weight in Java, Ruby and
PHP**. Nothing imports a controller — the framework dispatches into it — so
precise resolution correctly finds zero references, and the module then drops
out of detector scope. For a controller that discards the exact file where
untrusted input enters the system. Precision without this convention is worse
than the tally it replaced.

The mechanism already existed for Python (`__main__.py`, `bin/`, `scripts/`,
`tests/`). Packs now declare `entry_point_patterns` for the paths their
framework dispatches into: controllers, jobs, mailers, migrations, servlets,
tests. Only the owning pack's patterns are consulted, so a Rails path convention
cannot vouch for a Go file that happens to sit under `app/controllers/`. The
convention is not a blanket amnesty either — an orphaned service beside a
recognised controller stays dead weight.

C and C++ remain on the filename tally, and triage still declares that.
