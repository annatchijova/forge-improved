# Seeded recall corpus

FORGE measures detector recall on intentionally seeded defects, not by
re-running only on carefully maintained repositories.  The measured unit is
the exact finding identity `(family, path, line)` emitted by the relevant
agent.  Severity is a secondary assertion; it never substitutes for locating
the seeded defect.

Run it from the repository root:

```bash
python3 -m forge.recall --corpus tests/corpus
```

The corpus manifest contains three distinct kinds of case:

| Kind | Contract | Included in recall denominator? |
|---|---|---|
| `positive` | Its exact identity must be emitted. | Yes |
| `benign_twin` | The specified family must emit nothing for that fixture. A hit is a precision regression. | No |
| `out_of_scope` | A real defect class FORGE does not currently model; it is recorded with its observed result. | Never |

`detection_mode: induction` and `both` enable the existing isolated induction
harness. Static cases remain static: they do not acquire a confirmation claim
merely because a harness exists for another family.

## Canonical forms and realistic variants

Positive cases are tiered. Existing canonical positives are the detector's
contract floor; a missing `tier` is retained as backwards-compatible spelling
of `canonical`. They gate at `recall >= 0.90` for every represented modeled
family, with zero hits on benign twins.

Variant positives measure the width of a family: aliases, alternative sinks,
different interpolation forms, imports, and other patterns found in neglected
code. Every variant declares a pre-run `expected_today` (`HIT`, `MISS`, or
`UNKNOWN`) and a disposition: `close_gap`, `scope_boundary`, or `undecided`.
The report emits canonical and variant recall separately, hypothesis
mismatches, and the known-gap ledger.

Variants do not lower the canonical gate. Their baseline in
`tests/corpus/recall-variants-baseline.json` prevents coverage regressions and
requires every current non-boundary miss to be explicitly enumerated. A miss
is never resolved by rewriting its fixture into a canonical shape. Moving a
variant to `scope_boundary` requires a documented decision; the baseline may
move upward after coverage improves, never silently downward.

The result is deterministic for a given commit and manifest, so the JSON
emitted by the command can be stored alongside any benchmark run and compared
across commits.

## Current measured baseline

The canonical corpus remains 29/29 (`1.0`) with zero benign-twin hits. The
realistic-variants corpus is 27/36 (`0.75`) after the second gap-closure lot.
That increase came from import spellings for unsafe deserialization, extended
credential targets, local path-expression flow, and SQL/command interpolation
or aliases; it is not a claim of family-complete coverage. The remaining
non-boundary misses stay in the baseline as visible backlog. See
[`recall-gap-closure-lot-1.md`](recall-gap-closure-lot-1.md) for exact
fixtures and limits, and [`recall-gap-closure-lot-2.md`](recall-gap-closure-lot-2.md)
for the SQL/command work.

## Scope is not a cleanliness certificate

The out-of-scope fixtures deliberately include business-logic exception
swallowing, `None`/index errors, state-machine errors, races, IDOR,
misused API returns, type errors, and resource leaks. They are not false
negatives in this measurement because FORGE does not claim to model those
families today.

Consequently, `COMPLETE_NO_FINDINGS` always means no surviving finding within
the declared source and detector scope. It never means “this repository has no
bugs.” A future detector family may promote an out-of-scope fixture into a
positive only alongside an explicit scope and contract change.
