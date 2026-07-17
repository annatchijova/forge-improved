"""Structural check for persistent audit/ledger appends without hash linkage."""
from __future__ import annotations

import ast

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import call_name, live_python, parse, source_finding


class TamperEvidentAuditChainSkill:
    contract = SkillContract(
        "tamper-evident-audit-chain", "1.0",
        ("persistent audit/ledger entries visibly link to the preceding entry hash",),
        ("ledger/audit append or write without prev_hash/entry_hash/chain evidence",),
        ("AST source evidence of the append function",),
        ("recognizes direct Python naming only; storage adapters and independently verified external chains are undetermined",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        source = context.source.lower()
        signal = "audit_or_ledger" in context.domain_hypothesis.domains and (".append(" in source or ".write(" in source or ".execute(" in source)
        return live_python(context, signal)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        findings = []
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            body = ast.get_source_segment(context.source, function) or ""
            lowered = body.lower()
            # FP guard: ordinary logging is diagnostic, not an append-only ledger.
            if not any(token in (function.name.lower() + " " + context.module.path.lower() + " " + lowered) for token in ("ledger", "audit", "chain", "provenance")):
                continue
            writes = [node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "write", "execute"} and not call_name(node).startswith("logging.")]
            if not writes or any(token in lowered for token in ("prev_hash", "entry_hash", "audit_hash", "chain_hash")):
                continue
            detail = "persistent audit/ledger append has no visible link to a previous entry hash"
            findings.append(source_finding(context, self.contract.name, writes[0], detail, "A plain append-only record cannot detect deletion, insertion, or reordering after the fact."))
        return tuple(findings)
