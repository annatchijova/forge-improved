# MCP Demo Prompt — Forge audit of phylo

Use this prompt with the MCP-connected Forge agent:

```text
You are running a Forge security-audit demo.

Audit the repository at /home/labestiadevigia/phylo using the Forge MCP audit
workflow. First run the repository preflight and report the detected stacks,
module count, connected-alive scope, dead-weight modules, and fossil/high-risk
modules. Then run the audit with:

- output directory: /tmp/forge-phylo-demo-audit
- max connected modules: 100

Before the audit, run the fail-closed red-team gate. If any red-team test
fails, stop and report the failure; do not present a green audit.

The audit must be bounded and must not hang on generated code, minified files,
unterminated string literals, or large artifacts. Treat .git, node_modules,
.next, .turbo, dist, build, target, caches, and binaries as generated or
excluded content unless Forge explicitly reports otherwise.

For the final English demo report, include:

1. detected languages and analyzed files;
2. findings grouped by language, severity, agent, and epistemic status;
3. discarded or downgraded candidates, with the reason;
4. abstentions and exact scope-boundary reasons;
5. whether each result was cross-checked by ARGOS or another independent
   evidence source;
6. red-team and full-suite test results;
7. runtime, memory, coverage, artifact integrity, and reproducibility notes;
8. a clear distinction between confirmed evidence, inferred concerns, and
   unknowns.

Do not call a result a false positive merely because it looks suspicious or
because another agent disagrees. Label it as confirmed, inferred, rejected,
or undetermined and cite the file/line evidence. Do not claim that a language
was audited when Forge only detected it or abstained due to missing support.

Write the Markdown report to:
/home/labestiadevigia/forge/resultados/phylo-demo/report.md

Also preserve the machine-readable Forge artifacts in that same directory.
At the end, print the report path, the exact audit command/tool invocation,
the commit or repository revision audited, and a short demo-friendly summary.
```
