# FORGE audit report

Repository: `/home/labestiadevigia/forge`
Seal: **VERIFIED**
Findings: **5** · Discarded hypotheses: **1**
Coverage: **66/755 (8.7%)**

## Repository profile

- Modules: 66 (39 connected)
- Domains: cryptographic, input_boundary, machine_learning
- Audit duration: 1.693817 seconds

## Findings

### HIGH · forge/reporting.py
- Agent: `bug_investigator`
- Status: `CONFIRMED BY INDUCTION`
- Description: The parser call `render_report(required["triage"], required["hypotheses"], required["sealed"], main, required["coverage"], json.loads(required["metrics"].read_text()))` at forge/reporting.py:43 has no nearby exception handling, so malformed input may escape as an opaque failure.
- Reasoning: Malformed input raised opaque FileNotFoundError. Evidence: forge/reporting.py:43: FileNotFoundError: incomplete FORGE run; missing: {not valid json/triage-manifest.json, {not valid json/hypotheses-manifest.json, {not valid json/verification-manifest.sealed.json, {not valid json/coverage-report.json, {not valid json/metrics.json
- Source commit: unavailable (source evidence retained)

### MEDIUM · forge/benchmark.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `93c616260be01e8d581b12fb3338315f92739a31`

### MEDIUM · forge/report.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `0000000000000000000000000000000000000000`

### MEDIUM · forge/report.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `0000000000000000000000000000000000000000`

### MEDIUM · forge/report.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `0000000000000000000000000000000000000000`

## Limitations

- Hypotheses require module 3 verification; parser candidates may receive isolated induction, while unsupported families remain AST-only.
- 689 discovered file(s) were skipped; see skipped_reasons for the exact paths and policy categories.
- 27 triaged module(s) were outside CONNECTED_ALIVE audit scope.
- 27 skill applicability result(s) were UNDETERMINED; no conclusion was inferred for them.
- 1 hypothesis/hypotheses survived structural verification without dynamic induction; they remain plausible hypotheses, not confirmed defects.
