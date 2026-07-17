# VIGÍA honest-degradation breadth audit — 2026-07-17

## Purpose and boundary

This was a read-only breadth calibration of FORGE's executable
`honest-degradation` skill against VIGÍA revision `2eb931b5`. It is not a
sealed FORGE report, not a census of VIGÍA defects, and not a claim that every
candidate below is a bug. Its purpose was narrower: determine whether the
skill's corpus precision survived contact with a carefully maintained,
forensic codebase, and preserve the adjudication trail.

The initial run produced 46 `PROTOCOL_GAP` candidates in 501 modules. Every
candidate was classified `CONNECTED_ALIVE`; module class therefore did not
separate production from tooling. After the F7 false-positive correction below,
the queue is 45 candidates: 41 production paths, three scripts, and one test.
That count is a triage queue, **not** a reported precision rate.

## A false positive that strengthened the skill

FORGE initially flagged `vigia/sift/sift_orchestrator.py::_to_signal_safe`.
That finding was false positive under VIGÍA's F7 repair pattern: the method
records conversion failures in `self._signal_drops`, returns an explicit
`_unanalyzed_signal(...)` for primary conversion failures, and exposes the
drop ledger to the final result. The failure is structurally visible rather
than silently represented as clean analysis.

The cause was in FORGE, not VIGÍA: the skill recognized `dropped` but not the
real ledger name `*_drops`, and it did not recognize a returned
`*_unanalyzed_*` marker. Commit `db587b2` corrects both forms. The permanent
regression is `variant-honest-degradation-returned-unanalyzed`, tagged
`regression_of: B-089`; it protects the real F7 pattern rather than a
simplified mock.

This is recorded as FP-007 in the false-positive ledger. After the correction,
the governance-skill variants remain 3/3 with zero benign-twin hits.

## Confirmed VIGÍA defects found during adjudication

### Registry timeout represented as clean zero

`vigia/sift/registry_timeline_reconstructor.py::RegRipperInterface.run_plugin`
catches `subprocess.TimeoutExpired` and `FileNotFoundError`, then returns the
same empty string used for legitimate empty plugin output. Induction with a
patched timeout confirmed that this flows through `analyze_hive()` as empty
findings and score zero; `RegistryAnalysisResult.to_signal()` emits no
`UNANALYZED` marker. The SIFT F7 fallback is only reached if `analyze_hive()`
raises, which this path does not.

This is a real honest-degradation defect: inability to analyze is represented
as an ordinary clean result. No VIGÍA source was changed during this read-only
audit.

### Partial engine attestation represented as complete

FORGE first marked the duplicate helper
`vigia/core/bundle_builder.py::BundleBuilder.compute_engine_attestation`.
That helper has no callers in the audited tree, so it must **not** be described
as the reachable finding. It was an evidence lead.

Following that lead revealed the live duplicate
`vigia/pipeline/pipeline.py::VigiaPipeline._compute_attestation()`. It
suppresses an `OSError` while collecting engine sources, hashes the reduced
set, and supplies the resulting 64-character SHA-256 value to
`BundleBuilder.seal()`. The R4 verifier checks only that the field is lowercase
hex of the expected length.

Induction patched one real source read to fail. The complete and partial runs
produced different, valid-looking 64-character hashes, and R4 accepted the
partial hash. This confirms an integrity defect: a partial source set is
presented as a complete engine attestation.

The provenance matters: FORGE did not flag the live function. It flagged the
dead duplicate, and human/Codex adjudication followed the duplicated mechanism
to the reachable defect. The live function is a current FORGE false negative.
It uses `except OSError: pass`, then sends the reduced collection through
`join -> sha256`; the current skill recognizes neither that flow nor
`_compute_attestation` as a required stage.

A targeted hash/sigil sweep examined 36 broadly related functions. Only these
two duplicated attestation helpers shared the exact shape: aggregate source
files, suppress source I/O, then make a SHA-256 integrity claim. This supports
a future, narrow honest-degradation subpattern: reduced coverage feeding a
hash/digest/attestation/seal without an explicit coverage manifest. It is not
implemented yet. The future rule must distinguish this from best-effort
indexing that records a count or limitation.

### CAIE artifact drop: P2 coverage disclosure gap

`vigia/core/forensic_adapter.py::_caie_artifacts_from_raw_results` skips a
malformed `raw_score` with `continue`. Induction showed that the original raw
result remains available while `context.caie_artifacts` becomes empty. The
pipeline later logs “no artifacts to analyze” and seals without distinguishing
“no evidence arrived” from “evidence arrived but could not be analyzed.”

This is a P2 coverage-disclosure gap, not a P1 verdict-flip claim. The path
feeds pipeline CAIE annotation; VIGÍA records B-062/B-094 separately for the
score-coupled CAIE path. The direct evidence did not show this adapter drop
changing the sealed decision. A future VIGÍA repair should preserve a dropped
artifact count/marker; it was not implemented during this FORGE audit.

## Scalar-return adjudication completed so far

| Candidate class | Result | Reason |
|---|---|---|
| `BundleBuilder.compute_engine_attestation` | Evidence lead | Dead duplicate; led to the live partial-attestation defect above. |
| `VigiaPipeline.generate_narrative` | Contextual FP | Optional post-seal narrative. |
| `CaseAdapter.artifact_to_signal` | Contextual FP | Caller collects warnings and raises when no usable signals remain. |
| `RegRipperInterface.run_plugin` | Confirmed defect | Timeout / missing executable becomes clean empty output. |
| `SiftOrchestrator._safe_engine` | Contextual FP | Later F7 handling materializes missing-engine state for input artifacts. |
| `AdversarialNLP._export_pdf` | Contextual FP | Optional report export; it does not alter analysis or verdict. |

Only the `_to_signal_safe` F7 false positive has been added to FORGE's
precision corpus so far. The other contextual adjudications are retained here
as evidence; they must receive focused regression fixtures before being claimed
as corpus coverage.

## Next work, deliberately bounded

1. Adjudicate the 12 loop-`continue` candidates and six scalar returns by
   input, output, and consuming decision/integrity path.
2. Sample (not silently census) the 21 direct-`pass` candidates if early review
   confirms they are cleanup/best-effort cases; report the sample size plainly.
3. Build the narrow attestation subpattern only after the triage evidence is
   sufficient, with a dogfood case for FORGE's former UTF-8 sample-boundary
   scope bug.
4. Keep VIGÍA fixes separate from this read-only FORGE calibration.

The principal lesson is not “46 bugs.” It is that a deterministic detector can
provide reproducible leads, while adjudication preserves the distinction among
real defects, contextual false positives, unmodeled classes, and detector false
negatives.
