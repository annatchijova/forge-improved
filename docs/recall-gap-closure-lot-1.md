# Recall-gap closure — lot 1

**Date:** 2026-07-18  
**Method:** exact-identity seeded recall, adversarial variant fixtures, and
precision guardrails  
**Status:** implemented and measured

This record covers the first intentionally bounded recall-improvement lot. It
does not claim that FORGE detects every instance of these bug classes. It
records which realistic syntactic variants became observable, why, and which
ones intentionally remain outside this change.

## Measured result

| Measure | Before lot 1 | After lot 1 |
|---|---:|---:|
| Canonical recall | 29/29 (1.0) | 29/29 (1.0) |
| Variant recall | 12/36 (0.333333) | 23/36 (0.638889) |
| Benign-twin false positives | 0 | 0 |
| Precision corpus | 1.0 | 1.0 |

The variants baseline is deliberately separate from the canonical gate. A
variant HIT counts only when the detector emits the expected
`(family, path, line)` identity. The runner also preserves the mechanism check
for variants where a generic finding could otherwise be incidental.

## Closed clusters

| Family | Shared mechanism | Variants closed | Current variant result |
|---|---|---|---:|
| `unsafe-deserialization` | Module-level import alias resolution plus dangerous YAML loader normalization | `import pickle as p`, direct `from pickle import loads`, `yaml.unsafe_load`, `yaml.full_load` | 4/4 |
| `hardcoded-credential` | Credential-shaped assignment-target extraction, including attributes, mapping keys, and direct dict entries | `config["password"]`, `self.api_key`, `{"password": literal}` | 3/4 |
| `path-traversal` | Intra-function unsafe-origin fixpoint, composed sanitizer barriers, and positional/keyword sink arguments | concatenation, one-hop alias, f-string, `open(file=...)` | 5/7 |

Each expansion has positive fixtures, benign twins, and a commit-local
baseline increase. The broadened detectors preserve the prior canonical
identities; this is checked alongside the complete precision corpus.

## Boundaries retained deliberately

- `Path(user_path).read_text()` remains an undecided `pathlib` sink policy;
  this lot does not silently treat it as covered.
- Literal credential concatenation remains a `scope_boundary`. Treating every
  string expression as a secret requires an explicit obfuscation policy and a
  separate false-positive analysis.
- Import aliases are resolved only at module level. A function parameter or
  local assignment that shadows the alias is not treated as proof of a risky
  deserialization call.

These are visible in `tests/corpus/recall-variants-baseline.json`, not removed
from the measurement merely because they remain unsupported.

## Post-lot consolidation

Before reusing local path flow for more injection families, the path mechanism
received a focused consolidation pass:

- Flow snapshots are now built once per function and queried at each call,
  instead of walking the function and converging aliases for every sink. Source
  order still prevents a later sanitizer from protecting an earlier `open()`.
- A parameter used only as a mapping key or subscript index of an external
  container is not treated as the path value: `open(config.get(user_path))`
  and `open(config[user_path])` are benign twins. The symmetric positives
  `open(user_path[1:])` and `open(user_path.get("path"))` remain findings,
  because the parameter is then the path-bearing container.
- The former `float("inf")` decision sentinel was removed. A directed AST
  self-audit guards the path-flow implementation against reintroducing a
  `float()` call there. This is stronger evidence for this path than relying
  on the Integrity Inspector, whose current float detector is intentionally
  scoped to float calls that reach a return.

The credential dict pattern has a different result. A UI label such as
`{"password": "Enter your password"}` is structurally indistinguishable from
a passphrase under the current direct-AST rule. It is recorded as accepted
limitation FP-005 in [`false-positive-ledger.md`](false-positive-ledger.md),
not suppressed by a sentence-like-string heuristic that would create a silent
false negative for real passphrases.

## Evidence and reproduction

The commits are `f42fa6a` (deserialization), `a85c285` (credentials), and
`39b94e9` (paths). Each includes the Terra co-author trailer and its own
positive/negative regression coverage.

Run from the repository root:

```bash
python3 -m forge.recall --corpus tests/corpus
python3 -m forge.precision --corpus tests/corpus --min-precision 0.95 --min-recall 0.90
python3 -m pytest -q
```

The expected post-lot-1 variant baseline is 23/36 with 11 non-boundary known
gaps. A later run may improve this value, but it must not lower it silently or
remove a miss without an explicit scope decision.
