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

## Safety and provenance

FORGE remains read-only against audited repositories. Manifests carry schema versions and module-path references so triage and hypotheses can be cross-checked. Hypotheses are not findings and must not be rendered as confirmed conclusions.
