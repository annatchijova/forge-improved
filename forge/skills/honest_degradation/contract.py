"""Executable structural subset of skills-gpt/honest-degradation.md."""
from __future__ import annotations

import ast

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import call_name, live_python, parse, source_finding


class HonestDegradationSkill:
    contract = SkillContract(
        "honest-degradation", "1.0",
        ("degraded input paths fail visibly or disclose their state",),
        ("silent exception fallback", "required deserialized field filled by a default"),
        ("AST evidence of a fallback body or deserialized payload access",),
        ("direct Python AST only; aliases, framework error handlers, and downstream flag consumers are not resolved",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        return live_python(context, "except" in context.source or ".get(" in context.source or "getattr(" in context.source)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        findings = []
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            body = handler.body
            # FP guards: reraising, named errors, logging/warnings, and an
            # explicit error/degraded flag are visible disclosure paths.
            names = {call_name(node) for stmt in body for node in ast.walk(stmt) if isinstance(node, ast.Call)}
            has_raise = any(isinstance(node, ast.Raise) for stmt in body for node in ast.walk(stmt))
            has_disclosure = any(name.startswith("logging.") or name in {"warn", "warning", "warnings.warn"} for name in names)
            has_flag = any(isinstance(node, (ast.Assign, ast.AnnAssign)) and any(token in " ".join(ast.unparse(target) for target in ([*node.targets] if isinstance(node, ast.Assign) else [node.target])).lower() for token in ("error", "failed", "invalid", "degraded", "warn")) for stmt in body for node in ast.walk(stmt))
            silent_return = any(isinstance(node, (ast.Return, ast.Pass)) for stmt in body for node in ast.walk(stmt))
            if silent_return and not (has_raise or has_disclosure or has_flag):
                detail = "exception handler returns a plausible fallback without raising, logging, or marking degraded state"
                findings.append(source_finding(context, self.contract.name, handler, detail, "A degraded-input handler is structurally silent, so callers cannot distinguish fallback data from verified data."))

        deserialized: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and call_name(node.value) in {"json.loads", "pickle.loads", "yaml.load", "yaml.safe_load"}:
                deserialized.update(target.id for target in node.targets if isinstance(target, ast.Name))
        required_tokens = {"id", "version", "schema", "hash", "signature", "payload", "data"}
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            receiver = None
            key_node = default = None
            if isinstance(call.func, ast.Attribute) and call.func.attr == "get" and len(call.args) >= 2:
                receiver, key_node, default = call.func.value, call.args[0], call.args[1]
            elif isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 3:
                receiver, key_node, default = call.args[0], call.args[1], call.args[2]
            if not isinstance(receiver, ast.Name) or receiver.id not in deserialized or key_node is None or default is None:
                continue
            key = key_node.value.lower() if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str) else ""
            if key not in required_tokens or (isinstance(default, ast.Constant) and default.value is None):
                continue
            detail = f"deserialized required field `{key}` is silently supplied by a default"
            findings.append(source_finding(context, self.contract.name, call, detail, "The parser fallback does not expose that required artifact input was absent."))
        return tuple(findings)
