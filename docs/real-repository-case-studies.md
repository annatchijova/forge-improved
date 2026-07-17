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

Stylometry was a real repository that had won a Google hackathon. It had not
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
It separates a corpus-backed false positive, a registry timeout represented as
clean zero, a partial-attestation defect reached through a dead duplicate, and
the live pattern that FORGE still missed. That document is deliberately more
precise than a finding count.

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
