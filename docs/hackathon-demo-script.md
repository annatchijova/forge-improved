# FORGE — three-to-five minute judge demo

The demo presents FORGE as an investigation instrument, not an oracle. Keep
the sealed artifact and its HTML report visible throughout; the important story
is the boundary between a deterministic lead and a human/agent adjudication.

## 1. Run a local audit (about one minute)

From the repository root:

```bash
python3 -m forge audit tests/corpus/demo_connected \
  --output-dir /tmp/forge-demo-run --summary
```

Open the generated standard report:

```bash
python3 -m forge report /tmp/forge-demo-run/verification-manifest.sealed.json \
  --mode standard -o /tmp/forge-demo-run/report.html
```

Point out the two independent boundaries in the coverage block:

> files parsed · modules in detector scope · modules outside detector scope.

The report also shows each surviving record's **Lead status** (`CODE FACT`,
`PROTOCOL_GAP`, or `PLAUSIBLE HYPOTHESIS`) before its description. The count is
not presented as a bug count.

## 2. Show the seal and abstention boundary (about one minute)

Use the report's seal and detector-scope sections. Explain that a clean result
means no surviving lead within both declared scopes. It does not certify that
unmodeled classes are absent. Then verify the exact artifact:

```bash
python3 -m forge verify /tmp/forge-demo-run/verification-manifest.sealed.json
```

The same report can be rendered at `summary`, `standard`, and `extended` tiers;
the renderer reads the sealed finding set and does not recompute detectors.

If the repository exceeds the bounded connected-module limit, FORGE produces
independent shards instead of inventing a parent seal. Render the navigation
index with:

```bash
python3 -m forge report /tmp/forge-demo-run
```

Open `forge-report-shards.html` first, then choose a shard's standard report.

## 3. Show the real VIGÍA case (about two minutes)

Open the preserved HTML artifacts in
`results/vigia-full-battery-20260717/`, then open
`docs/real-repository-case-studies.md`.

Tell the case in this order:

1. FORGE emitted a deterministic `honest-degradation` lead in CAIE's timestamp
   parser.
2. A bounded human/agent experiment changed one timestamp from parseable to
   malformed while keeping the rest of the evidence identical.
3. The temporal fracture disappeared and the sealed verdict changed from
   `SUSPICION (0.4549)` to `NOISE (0.0192)` without a coverage marker.
4. The follow-up fix belongs in VIGÍA; FORGE does not rewrite its original lead
   into a retroactive detector success.

Mention the complementary lesson: FORGE also documented a false positive and a
known false negative. That is evidence of a governed workflow, not a weakness
to hide.

## Closing sentence

> FORGE makes the search deterministic and the uncertainty visible; the final
> claim still belongs to the evidence and the investigator.

The companion projects demonstrate the same boundary in different domains:
LIFELINE keeps dispatch human-approved, and Continuum keeps memory access and
classification in its deterministic core while treating narration as optional.
