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

`hypotheses._candidates()` intentionally surfaces only `candidates[:5]` per
module. A module that triggers more than five distinct risk patterns therefore
has later candidates omitted. This is a known completeness limitation, not
evidence that the omitted patterns were absent — and, as of 2026-07-15, it is
surfaced rather than silent: `generate_hypotheses()` adds one entry per capped
module to `HypothesesManifest.limitations` (`"<module>: N additional risk
pattern(s) ... omitted"`), so it reaches the manifest and the report instead
of only living in this document.

## Executable skill runtime boundary

Skills are executable, versioned contracts loaded from local plugin manifests.
FORGE's core owns discovery, read-only context, applicability recording, typed
evidence, sealing, and reporting; a skill owns its domain-specific methodology.
Domain classification is an evidence-backed hypothesis per module, not a
repository-wide fact, and `UNDETERMINED` is retained when evidence cannot
justify applicability. Only the `validate-at-the-boundary` skill is currently
migrated as a complete reference contract; the remaining markdown skills are
not yet executable plugins and must not be represented as active checks.

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
