# Real-repository case studies

These case studies are public evidence of how FORGE is intended to be used:
the runtime produces a deterministic, reviewable signal; a human or Codex then
adjudicates whether the signal is a real defect, a contextual false positive,
or an unresolved hypothesis.

The repositories were not seeded with bugs for this demonstration. Their
history is public, and the audited snapshots can be compared with the
repositories themselves.

## Stylometry — external repository, honest false positives

Repository: [GitHub: annatchijova/stylometry](https://github.com/annatchijova/stylometry) · [GitLab mirror](https://gitlab.com/anna.tchijova/stylometry)

Stylometry was a real, independently recognized repository. It had not
been modified for approximately a month before the audit, and no defects were
introduced for the demo. FORGE ran against a fixed public revision and emitted
sealed artifacts and HTML reports that are available in the public
[`forge-results`](https://github.com/annatchijova/forge-results) evidence
repository.

The first pass contained contextual false positives, including serialization
patterns in tests and exporters and heuristic numeric findings. Those were not
presented as confirmed vulnerabilities. Codex reviewed the evidence against
the source tree and separated:

- contextual false positives and unproven design debt;
- a GitLab delivery failure that had been silently swallowed; and
- a numeric contract mismatch where entropy functions were annotated as
  returning `Fraction` while returning floating-point values.

The confirmed issues were corrected in Stylometry and committed as
`034069c` (`fix: address confirmed FORGE audit findings`), then pushed to the
public repository. The correction preserves delivery outcomes explicitly and
uses a documented rational approximation for entropy values. The false
positives remain part of the audit story: reproducible noise is inspectable,
classifiable, and useful for improving the detector corpus.

## Vigia — a false positive that led to a real bug

Repository: [annatchijova/vigia-intent-analysis](https://github.com/annatchijova/vigia-intent-analysis)

In Vigia, an initial FORGE signal looked like a contextual false positive.
Instead of discarding it, Codex followed the evidence through the surrounding
code and runtime behavior. That investigation uncovered a separate, real bug
behind the original signal. The bug was fixed, committed, and pushed to the
repository.

This is an important boundary claim: the original FORGE finding is not
retroactively relabeled as a confirmed defect. The value was in using a
deterministic, reproducible signal as a lead for a second investigation. The
human/agent review supplied the additional reasoning and verification; FORGE
preserved the initial evidence and did not silently rewrite its verdict.

The subsequent read-only breadth audit of the executable
`honest-degradation` skill is recorded in
[`vigia-honest-degradation-breadth-2026-07-17.md`](vigia-honest-degradation-breadth-2026-07-17.md).
It is a second, distinct demonstration of the workflow. The audit contains
false positives that strengthened FORGE's corpus, a registry timeout represented
as clean zero, a partial-attestation defect first reached through a dead
duplicate, and an induced live decision flip caused by silent normalization of
CAIE-bound evidence. It also records the cases that remain only component-level
or unresolved. That is deliberate: FORGE prepares a falsifiable investigation;
it does not replace adjudication with a claim of universal truth.

### CAIE timestamp coverage lead — confirmed only after bounded induction

FORGE also emitted a deterministic `honest-degradation` lead in CAIE's
timestamp parsing path: an exception-handled parsing failure could reduce
temporal-analysis coverage without a structural marker in the returned result.
That emission was a reproducible code fact, not a proven vulnerability.

A subsequent human/agent investigation constructed two otherwise identical
artifacts. With parseable timestamps, CAIE detected one
`TEMPORAL_CAUSALITY_VIOLATION` and the sealed pipeline produced
`SUSPICION` (`0.4549`). Replacing one required timestamp with an unparseable
value caused CAIE to omit the comparison, return zero fractures, and seal
`NOISE` (`0.0192`) without a coverage marker. The HMAC audit log records the
parse error, but the CAIE result and sealed decision did not distinguish
“evaluated clean” from “not evaluated.”

This is the intended evidence chain: FORGE supplied the deterministic lead;
the follow-up investigation proved reachability and impact; VIGÍA receives a
separate fix that preserves skipped temporal-pair coverage and abstains rather
than sealing a clean result when decision-relevant analysis was omitted.

## What these runs demonstrate

FORGE is not a guarantee that a repository is bug-free. It is a governed
workflow:

1. inspect a declared snapshot deterministically;
2. preserve evidence, scope, hypotheses, and limitations;
3. let a reviewer adjudicate findings against the source and, when useful,
   execute a bounded verification;
4. fix confirmed defects in the target repository; and
5. add confirmed false positives and regressions back to the corpus.

The public artifacts make it possible for judges to inspect both the original
signals and the subsequent engineering decisions rather than trusting a
marketing summary.
