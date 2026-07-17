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

- `COMPLETE_NO_FINDINGS` — the declared source scope was verified and no
  finding survived;
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
