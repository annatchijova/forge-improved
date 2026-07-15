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
3. **Eval/exec.** Dynamic evaluation is benign only when its argument is an `ast.Constant` string literal. Variables, concatenations, attributes, and all other expressions remain findings because their provenance is not structurally constrained.
4. **Subprocess.** A subprocess call is benign only when its `ast.Call` has a real `ast.Try` ancestor with an explicit subprocess-related handler (`subprocess.SubprocessError`, `OSError`, or a named equivalent). A generic catch does not establish a safe boundary.

`VerificationManifest` must report these four families as `AST-verified`; any family without an implemented structural checker is explicitly `unverified — falls through to PLAUSIBLE HYPOTHESIS without structural check`.
