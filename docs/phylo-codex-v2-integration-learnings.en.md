# Integration lessons from the `phylo-codex-v2` audit

Date: 2026-07-16  
Audited repository: `/home/labestiadevigia/phylo`  
Audited revision: `26cfd2d22c0d22b5a1a883922909989476579804`  
Run artifacts: [`resultados/phylo-codex-v2/`](../resultados/phylo-codex-v2/)

## Executive conclusion

The v2 run improved agent independence and correctly abstained from claiming
confirmed vulnerabilities. The red-team gate passed 8/8, the Forge suite
passed 155/155, eight distinct work-product digests were recorded, and the
sealed manifest verified successfully.

However, the final artifacts are not yet one coherent multi-agent audit. The
Codex agents produced six external hypotheses, while the Forge-native sealed
manifest contains seven older deterministic findings. The report, findings
JSON, comparison, audit trace, and seal therefore describe different result
sets.

This is an integration and provenance defect in Forge, not a failure of the
agents' abstention reasoning.

## What was actually validated

- Eight external roles supplied distinct JSON work products.
- The independence artifact reported `INDEPENDENCE_VERIFIED`.
- The target repository was not modified.
- The red-team gate passed before the full suite.
- The full Forge suite passed: 155 tests.
- Seal integrity and chain linkage verified successfully.
- The target was not executed.
- Python received effective analysis; JavaScript/TypeScript received bounded
  lexical review.
- SQL, CSS, YAML, and MJS were detected but not effectively audited.
- ARGOS was unavailable and correctly recorded as abstained.

These are valid properties of the run.

## Critical integration defect: report and seal use different findings

The Codex-facing files contain six hypotheses, H1 through H6:

- unauthenticated or client-controlled persistence;
- wildcard API-key scopes;
- sandbox isolation and timeout behavior;
- Python path and error handling;
- bundle integrity, numeric, and provenance gaps.

The sealed Forge manifest contains seven different native findings:

- `tools/evolution_bundle.py:548`;
- `app/api/ci/route.ts:167`;
- `app/api/save-run/route.ts:107`;
- `app/api/save-run/route.ts:110`;
- two JavaScript `eval` observations;
- `app/api/sandbox/python/route.ts:226`.

Consequences:

- `findings.json` describes six Codex hypotheses;
- `report.md` presents those six hypotheses;
- `verification-manifest.sealed.json` seals seven native findings;
- the seal does not cover the six Codex hypotheses presented by the report;
- the report's claim of a verified seal is true, but it does not prove the
  report's six Codex hypotheses were sealed.

The correct fix is to create one canonical finding set after multi-agent
reconciliation and seal that exact set. Native Forge findings and external
Codex findings must either be merged with explicit provenance or be stored as
separate, clearly labeled layers.

## Comparison defect

`comparison.json` reports:

- seven previous findings;
- seven current findings;
- zero new;
- zero resolved;
- seven unchanged.

That comparison is between the previous Forge-native run and the Forge-native
findings embedded in v2. It does not compare the six Codex hypotheses against
the baseline.

The comparison layer must operate on the same canonical finding set that is
reported and sealed. Its input must include the finding-set identity, scope
hash, Forge revision, agent configuration, and skill versions.

## Independence validation is necessary but not sufficient

`agent-independence.json` proves that eight files contain distinct work-product
digests. It does not prove that:

- the agents ran in genuinely independent contexts;
- one agent did not copy another agent's evidence;
- the reviewer received a distinct view of the work;
- the work products entered the final Forge trace;
- each hypothesis has a complete A-D-I cycle.

The current A-D-I validator checks that the combined work product contains the
three stage names. It does not require every `hypothesis_id` to contain all
three stages. In v2, some agents distribute abduction, deduction, and induction
across different hypotheses.

Required validation rule:

```text
for every agent and every hypothesis_id:
    require exactly one abduction entry
    require exactly one deduction entry
    require exactly one induction entry
```

## Skills are inconsistently represented

The run declares a catalog of 20 skills, but the agent files are inconsistent:

- several specialist agents list 20 individual skill applications;
- `coordinator` lists one aggregate catalog entry;
- `scope_triage` lists one aggregate catalog entry;
- `independent_reviewer` lists one aggregate catalog entry.

Therefore the statement that all agents loaded all 20 skills is not supported
uniformly by the artifacts. The final schema must require the same skill record
shape for every role. A skill is `APPLIED` only when the work product contains
concrete evidence that the skill changed an analysis action or decision.

## Epistemic interpretation of the six hypotheses

The six Codex hypotheses are useful and appropriately remain `UNDETERMINED`.
The most consequential areas are:

1. unauthenticated persistence and client-controlled organization identity;
2. wildcard scope creation without visible delegation checks;
3. unauthenticated signing of caller-controlled bundle content;
4. shared or incompletely isolated sandbox execution;
5. partial bundle hash coverage and missing model provenance;
6. numeric and malformed-input behavior at verification boundaries.

The `HIGH` labels are static prioritization signals. They are not evidence of
exploitation, impact, or production severity. No candidate should be called a
false positive without an executed falsification test.

## Required P0 fixes before the next run

1. Build one canonical external-plus-native finding manifest.
2. Seal that canonical manifest, not the prior native runtime output.
3. Make `report.md`, `report.json`, comparison, trace, and seal consume the
   same finding-set digest.
4. Require complete A-D-I for every hypothesis ID.
5. Require all 20 skill records for every role, or explicitly record missing
   skills as `UNDETERMINED`.
6. Add external agent events and work-product digests to `audit-trace.json`.
7. Record the review dependency graph: which agents ran before the reviewer.
8. Compare the same canonical finding set across historical runs.

## Success criteria for the next run

The next run is integrated only if:

- `findings.json`, `report.md`, `report.json`, and the sealed manifest contain
  the same finding-set digest;
- the comparison uses that same canonical set;
- every agent and every hypothesis has complete A-D-I;
- every role has a consistent 20-skill ledger;
- the trace records external agent completion and review order;
- the final status distinguishes `INDEPENDENCE_VERIFIED` from
  `AUDIT_FINDINGS_SEALED`;
- abstention remains visible and no static hypothesis is promoted to confirmed
  without execution evidence.
