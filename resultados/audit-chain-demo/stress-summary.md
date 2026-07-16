# Forge Stress Test — audit-chain

Date: 2026-07-15

- Repository: `/home/labestiadevigia/audit-chain`
- Detected stacks: C, Java, Rust
- Preflight modules: 3
- Connected alive modules: 0
- Findings: 0
- Discarded findings: 0
- Disposition: `ABSTAIN_INSUFFICIENT_SCOPE`
- Coverage: 0/1
- Repeated runs: 3/3 semantically stable
- Runtime: 0.25 seconds per run
- Maximum resident memory: approximately 29 MB
- Red-team gate: passed (8 adversarial tests; 147 full-suite tests)

The result is an honest abstention: Forge detected C, Java, and Rust, but no
specialized analyzers were available for those source languages in this run.
Generated Rust `target/` artifacts were excluded from the audit scope.
