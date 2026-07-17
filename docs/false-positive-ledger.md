# FORGE false-positive ledger

This ledger is intentionally separate from findings. A false positive is a
post-audit adjudication with a reproducible cause, a rule change, and a
regression test. It is not silently deleted from history.

| ID | Source run | Trigger | Root cause | Rule refined | Regression | Status |
|---|---|---|---|---|---|---|
| FP-001 | FORGE self-audit | `float()` near `verdict`/`score` | Naming proximity was used instead of return data flow | Shallow assignment/return propagation | `test_integrity_ignores_unrelated_float_telemetry_but_flags_return_value` | Resolved |
| FP-002 | FORGE self-audit | `json.dumps(payload)` in benchmark | Versioned inline dict was assigned to a name the detector did not follow | Track named versioned payloads | `test_integrity_recognizes_versioned_named_payload` | Resolved |
| FP-003 | FORGE self-audit | JSON embedded in HTML dashboard | Presentation serialization was confused with persisted artifact serialization | Exclude presentation-only serialization | `test_integrity_ignores_json_embedded_in_presentation_html` | Resolved |
| FP-004 | FORGE self-audit | Missing local `try/except` around report rendering | Explicit boundary error was classified as opaque failure | Preserve named error contract; refine classification | Existing incomplete-run error tests | Classified as detector FP |
| FP-005 | Recall-gap consolidation | `{"password": "Enter your password"}` | A direct dict label is structurally indistinguishable from a passphrase under a credential-shaped key | No suppression rule: a label heuristic would hide real passphrases | `variant-credential-dict` remains a positive secret regression | Accepted limitation |

## Entry contract

Future entries must include:

1. the exact source run and finding identity;
2. the triggering code pattern;
3. the evidence proving the finding is false or duplicated;
4. the minimal rule refinement;
5. a regression that would fail under the old rule;
6. the resulting disposition: resolved, accepted limitation, or still open.

The ledger demonstrates deterministic learning: FORGE improves by refining
rules and tests, not by silently training on or suppressing findings.
