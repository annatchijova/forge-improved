# FORGE audit report

Repository: `/home/labestiadevigia/mutante`
Seal: **VERIFIED**
Findings: **19** · Discarded hypotheses: **0**
Coverage: **43/308 (14.0%)**

## Repository profile

- Modules: 43 (14 connected)
- Domains: cryptographic, input_boundary, machine_learning
- Audit duration: 2.08182 seconds

## Findings

### MEDIUM · agent_mutante/engine/semiotic_llm_judge.py
- Agent: `bug_investigator`
- Status: `PLAUSIBLE HYPOTHESIS`
- Description: The parser call `result = json.loads(raw)` at agent_mutante/engine/semiotic_llm_judge.py:113 has no nearby exception handling, so malformed input may escape as an opaque failure.
- Reasoning: Observed construct matches; induction was undetermined: Induction timed out after 1.0s; child process was terminated.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · apply_license.py
- Agent: `security_auditor`
- Status: `CODE FACT`
- Description: parameter reaches open() without proven normalization
- Reasoning: AST detector emitted this observation: path-traversal.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · apply_license.py
- Agent: `security_auditor`
- Status: `CODE FACT`
- Description: parameter reaches open() without proven normalization
- Reasoning: AST detector emitted this observation: path-traversal.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · main.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · main.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/bigquery_sink.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/bigquery_sink.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: unversioned serialization
- Reasoning: AST detector emitted this observation: unversioned-serialization.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_semiotic_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_hybrid_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/mutante_hybrid_evaluator.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/semiotic_llm_judge.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/quality_gate.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

### MEDIUM · agent_mutante/engine/quality_gate.py
- Agent: `integrity_inspector`
- Status: `CODE FACT`
- Description: non-deterministic arithmetic in a decision-adjacent path
- Reasoning: AST detector emitted this observation: decision-adjacent-float.
- Source commit: `58279bfa9c3f907806861b18377875d99e4e5c24`

## Limitations

- Hypotheses require module 3 verification; parser candidates may receive isolated induction, while unsupported families remain AST-only.
- 265 discovered file(s) were skipped; see skipped_reasons for the exact paths and policy categories.
- 29 triaged module(s) were outside CONNECTED_ALIVE audit scope.
- 13 skill applicability result(s) were UNDETERMINED; no conclusion was inferred for them.
- 1 hypothesis/hypotheses survived structural verification without dynamic induction; they remain plausible hypotheses, not confirmed defects.
