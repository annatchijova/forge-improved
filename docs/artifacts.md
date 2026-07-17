# Artifacts, not one giant JSON

A single `Runtime().audit()` run writes separate files rather than one
undifferentiated blob:

```
triage-manifest.json                every module's classification
hypotheses-manifest.json            candidates generated before verification
verification-manifest.json          findings + discarded, pre-seal
verification-manifest.sealed.json   the SHA-256 hash chain
coverage-report.json                discovered/analyzed/skipped, with reasons
skills-runtime.json                 governance-skill applicability + findings
metrics.json                        per-agent counts and examination summaries
audit-trace.json                    the CRONOS-derived event trace, sealed
forge-report.html                   the self-contained human-readable report
```

Splitting these on purpose, instead of nesting everything into one report
object, is what makes it possible to: reuse one stage's output without
recomputing the others; inspect a single stage in isolation when something
looks wrong; version each format independently as it evolves; and consume
any of it from MCP (`get_coverage`, `get_findings`, `verify_seal`, ...)
without parsing HTML.

## Sealing

Every completed `run_specialized_pipeline()` and `run_pipeline()` call
canonically serializes its `VerificationManifest` and seals it into a
SHA-256, append-only, genesis-anchored hash chain
(`forge/sealing.py::seal_manifest`).

The seal proves that sealed findings were not altered after sealing. It does
**not** prove the findings are correct, and it does not defend against a
full-access attacker forging a consistent replacement chain from scratch —
`DECISIONS.md` documents that boundary explicitly so it is never presented as
a stronger guarantee than it is.

## Evidence before confidence

FORGE reports what was actually inspected, using the real field names that
`run_specialized_pipeline()` writes to `coverage-report.json` and the report's
Quality Metrics table — not a rounded PR-deck summary:

```
files_discovered ................. every file under the audited root
files_analyzed .................... eligible source files reached by a built-in analyzer
eligible_source_files ............ built-in source types after policy/binary/size
                                     exclusions; semantic coverage denominator
files_skipped ...................... files_discovered - files_analyzed
skipped_reasons
  excluded_by_policy ............... policy directory or ignored file name
                                     (e.g. .venv, node_modules, prior results)
  oversized_file .................... file exceeds the 5 MiB source guard
  binary_file ....................... NUL-byte binary signal in the sample
  unreadable_file ................... I/O or permission failure while reading
  non_utf8_text ..................... text-like file that cannot decode as UTF-8
  syntax_error ....................... .py file that failed ast.parse
  non_python_not_analyzed ........... readable, not excluded, not .py

coverage_ratio ..................... files_analyzed / eligible_source_files
discovery_ratio .................... files_analyzed / files_discovered

audited_modules .................... modules read for hypothesis generation
findings (surviving) ............... entries in the sealed chain
discarded hypotheses ................ ruled out, kept with their reason
clean modules ........................ audited, zero surviving findings
out of scope .......................... not CONNECTED_ALIVE this run

chain_integrity ...................... OK / BROKEN (+ issues)
```

`coverage_ratio` is the reader-facing source-coverage claim. `discovery_ratio`
is filesystem-accounting context only: it includes deliberately excluded VCS
objects, images, prose, and unsupported languages, so it is not semantic source
coverage.

Every discovered file lands in exactly one bucket — `files_analyzed` or one
`skipped_reasons` entry — never both, never neither. That arithmetic
invariant is enforced by an adversarial regression test
(`tests/test_specialized_pipeline.py`), not just asserted in prose.
