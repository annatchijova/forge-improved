# Codex session record — governed recall and provenance work

**Repository:** `/home/labestiadevigia/forge`  
**Role:** Codex / ChatGPT 5.6 Terra, acting as implementer and red-team
recorder  
**Method:** abductive engineering (A-D-I), red-team auditing, exact evidence
and reversible Git checkpoints

This record explains what was implemented, what the evidence actually proves,
and where the work deliberately stops. It is a process record, not a claim
that FORGE is bug-free.

## Work completed

The session closed three classes of risk before measuring recall:

1. **Integrity/provenance (H1).** Native assembly attestation now uses a
   configured persistent `FORGE_ATTESTATION_KEY`, with an explicit
   `EPHEMERAL_UNVERIFIABLE` fallback. `verify_sealed()` exposes attestation
   state. External multi-agent findings remain allowed but are labeled
   `UNATTESTED` and force `ABSTAIN_UNATTESTED_EXTERNAL`; they are never
   auto-attested as if Codex had run a native FORGE audit.
2. **Silent degradations (H3/H4).** Same-line distinct sinks retain separate
   finding identities, and a crashing executable governance skill propagates
   an abstention/limitation instead of silently suppressing its finding.
3. **Seeded recall measurement.** `forge.recall` measures exact
   `(family, path, line)` identities. Positive fixtures are recall obligations;
   benign twins are precision guards; out-of-scope defects are recorded but
   excluded from the denominator. The result and a compact baseline are
   versioned with the commit.
4. **Clean-report language.** A real audit over a deliberately buggy but
   unmodeled repository must render `COMPLETE_NO_FINDINGS` with both source
   coverage and detector scope visible. The summary and standard report tiers
   are denylisted against repository-cleanliness claims.

The recall implementation also exposed and fixed one genuine scope gap:
`os.path.join(base, user_path)` was declared as a path-traversal operation but
the detector only recognized the malformed shape `os.path(...)`. The detector
now handles `os.path.<operation>` while excluding normalization barriers.

## What the current number means

The first seeded baseline is 29/29 positives across 18 represented families,
recall `1.0`, with zero benign-twin hits. This is a valid floor: every
canonical seeded shape currently modeled by the detector emitted its expected
identity, and all declared precision guardrails stayed clean.

It is **not** evidence that FORGE recognizes every real-world instance of
those bug classes. The initial fixtures were written from the detector
contracts, so they intentionally exercise canonical forms. A perfect result
therefore partly measures that the implementation agrees with its own
contract. It does not measure the width of the family.

That limitation is now explicit rather than hidden in the baseline. The next
recall layer is a variants corpus: realistic syntactic and data-flow forms
such as `open(user_path + ".txt")`, one-hop aliases (`p = user_path;
open(p)`), subscript credential assignments, and non-literal `eval(a + b)`.
A missed variant is recorded as a real recall gap/backlog item; the fixture is
not weakened to make the gate green.

## Language and scope boundary

The out-of-scope cases deliberately cover general business exception
swallowing, `None`/index errors, state transitions, races, IDOR, ignored API
returns, type errors, and resource leaks. They are not false negatives because
the current detector contracts do not model them. A report may complete with
no findings **within the declared scope**, but must not describe that result
as “no bugs” or a repository cleanliness certificate.

Before expanding variants, the next inexpensive safeguard is an end-to-end
report assertion: render a real FORGE report over an out-of-scope fixture and
verify that its disposition and prose preserve the scope qualifier. The
runner-level coverage statement is necessary but insufficient evidence for
that claim.

That safeguard is now implemented. The report has one detector-scope source
listing modeled families and representative unmodeled defect classes; the
disposition block also shows source coverage and says that
`COMPLETE_NO_FINDINGS` is bounded by both scopes.

## Variants baseline

The variants corpus contains 36 syntactic/data-flow alternatives across ten
families. Its semantically audited baseline is 12/36 (`0.333333`): deliberately
much lower than the canonical floor, because it measures family width rather
than a manual-form contract. Twenty-three non-boundary misses are recorded as
known gaps. The float-container prediction was a legitimate positive. The
interprocedural helper was corrected to a MISS at the decision site, and the
shell-variable result was marked an incidental generic-flow hit rather than
coverage of shell-flag resolution. The baseline fails only on coverage
regression or an unrecorded miss, not because an honest known gap exists.

## Recall-gap closure — lot 1

The first measured closure lot raised realistic-variant recall from 12/36 to
23/36 while preserving canonical recall (29/29), zero benign-twin hits, and
the precision corpus at 1.0. It did so through three bounded mechanisms:

1. module-level alias/direct-import resolution and YAML loader normalization
   for unsafe deserialization (4/4 variants);
2. direct credential-shaped mapping keys, attributes, and dict entries (3/4;
   literal concatenation remains a scope boundary); and
3. local unsafe-origin propagation through path expressions and keyword sinks
   with composed sanitizer barriers (5/7; `pathlib` remains undecided).

This is a depth improvement inside already modeled families, not evidence that
FORGE now covers unmodeled bug classes or every spelling of these families. The
specific fixtures, retained boundaries, and verification commands are in
[`recall-gap-closure-lot-1.md`](recall-gap-closure-lot-1.md).

Before the next injection-focused lot, path-flow was consolidated: snapshots
are computed once per function, lookup-key positions are distinguished from
path-bearing containers, and the float sentinel used in a security decision
was removed. The key-position benign twin is paired with positive slice and
container forms so the precision fix cannot silently become a path-traversal
false negative. A directed AST test, rather than the narrower return-oriented
Integrity Inspector, guards this deterministic-core invariant.

Lot 2 reused those snapshots for SQL and command injection. SQL now confines
taint to the query expression (argument zero), preserving bound values as a
safe channel; all four measured SQL variants hit. Command injection now
requires a shell-interpreted string command: `os.system`/`os.popen`, or
`subprocess` with literal `shell=True`. This closed the two modeled command
variants and corrected the prior argv-list false positive (FP-006). The
`shell=<variable>` variant remains an explicit undecided gap, not a claimed
coverage win.

## Reproducibility and checkpoints

The relevant checkpoints are:

- `e8148a4` — separate sealed assembly integrity from external analytical
  provenance (H1 closure).
- `daba864` and `ac30e4e` — document FORGE's runtime positioning and the
  phrase **Forensic governance runtime for reproducible software audits**.
- `596c658` — add the seeded recall runner, fixtures, baseline, tests, and
  scope documentation.
- `f42fa6a`, `a85c285`, and `39b94e9` — first bounded closure lot for
  deserialization imports, credential targets, and path expressions.

Validation after lot 1: the full test suite, precision corpus, and seeded
recall gate are green. Canonical recall remains `1.0` per represented family,
with zero twin FPs; variant recall is 23/36 and its known gaps remain visible.

## Decision discipline going forward

- Keep exact identity as the recall truth; severity and controllability remain
  secondary assertions.
- Keep out-of-scope cases outside the denominator.
- Preserve misses as measurable backlog entries rather than hiding them.
- Treat report wording as a security boundary: a clean scoped disposition must
  expose what was not analyzed.
- Use explicit commits with the Codex co-author line; never rewrite the
  history to erase an earlier baseline or a falsified hypothesis.
