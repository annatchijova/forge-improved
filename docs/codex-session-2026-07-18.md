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
families. Its first measured baseline is 14/36 (`0.388889`): deliberately much
lower than the canonical floor, because it measures family width rather than a
manual-form contract. Twenty non-boundary misses are recorded as known gaps;
three predicted misses were informative surprises where the detector already
covered more than expected (shell variable, container-held float, and a helper
return). The baseline fails only on coverage regression or an unrecorded miss,
not because an honest known gap exists.

## Reproducibility and checkpoints

The relevant checkpoints are:

- `e8148a4` — separate sealed assembly integrity from external analytical
  provenance (H1 closure).
- `daba864` and `ac30e4e` — document FORGE's runtime positioning and the
  phrase **Forensic governance runtime for reproducible software audits**.
- `596c658` — add the seeded recall runner, fixtures, baseline, tests, and
  scope documentation.

Validation at the pause point: full test suite `289 passed`; the seeded recall
gate is green at the canonical floor (`1.0` per represented family, zero twin
FPs). No variant-corpus claim has been made yet.

## Decision discipline going forward

- Keep exact identity as the recall truth; severity and controllability remain
  secondary assertions.
- Keep out-of-scope cases outside the denominator.
- Preserve misses as measurable backlog entries rather than hiding them.
- Treat report wording as a security boundary: a clean scoped disposition must
  expose what was not analyzed.
- Use explicit commits with the Codex co-author line; never rewrite the
  history to erase an earlier baseline or a falsified hypothesis.
