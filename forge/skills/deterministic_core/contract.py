"""Deterministic sealing checks, intentionally separate from ML verdict floats."""
from __future__ import annotations

import ast

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import call_name, live_python, parse, source_finding


def _is_hash_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and call_name(node).startswith("hashlib.")


def _contains(node: ast.AST, predicate) -> bool:
    return any(predicate(child) for child in ast.walk(node))


class DeterministicCoreSkill:
    contract = SkillContract(
        "deterministic-core", "1.0",
        ("sealed serializations are canonical and free of direct float/order leaks",),
        ("json dump reaches hash", "float or unordered iteration reaches sealed payload"),
        ("AST evidence of a seal input",),
        ("direct intra-module dataflow only; custom canonicalizers and aliases are recognized only by their canonical naming",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        signal = "determinism_sensitive" in context.domain_hypothesis.domains and ("hashlib" in context.source or "seal" in context.source.lower())
        return live_python(context, signal)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        findings = []
        unsafe_dumps: dict[str, ast.Call] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call) or call_name(node.value) != "json.dumps":
                continue
            if any(keyword.arg == "sort_keys" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.value.keywords):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    unsafe_dumps[target.id] = node.value
        for hash_call in (node for node in ast.walk(tree) if _is_hash_call(node)):
            if _contains(hash_call, lambda child: isinstance(child, ast.Call) and call_name(child) == "json.dumps" and not any(k.arg == "sort_keys" and isinstance(k.value, ast.Constant) and k.value.value is True for k in child.keywords)):
                detail = "non-canonical json.dumps output feeds a hash/seal without sort_keys=True"
                findings.append(source_finding(context, self.contract.name, hash_call, detail, "A seal over unordered JSON is not reproducible across equivalent mapping orderings."))
                continue
            used = {child.id for child in ast.walk(hash_call) if isinstance(child, ast.Name)}
            for name, dump in unsafe_dumps.items():
                if name in used:
                    detail = "non-canonical json.dumps output feeds a hash/seal without sort_keys=True"
                    findings.append(source_finding(context, self.contract.name, hash_call, detail, "A seal over unordered JSON is not reproducible across equivalent mapping orderings."))
                    break
        sealed_payloads: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and call_name(node.value) == "json.dumps" and node.value.args:
                if any(_is_hash_call(parent) and any(isinstance(item, ast.Name) and item.id in {target.id for target in node.targets if isinstance(target, ast.Name)} for item in ast.walk(parent)) for parent in ast.walk(tree)):
                    sealed_payloads.update(child.id for child in ast.walk(node.value.args[0]) if isinstance(child, ast.Name))
        for hash_call in (node for node in ast.walk(tree) if _is_hash_call(node)):
            for dump in (child for child in ast.walk(hash_call) if isinstance(child, ast.Call) and call_name(child) == "json.dumps" and child.args):
                sealed_payloads.update(child.id for child in ast.walk(dump.args[0]) if isinstance(child, ast.Name))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript) and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id in sealed_payloads:
                if _contains(node.value, lambda child: isinstance(child, ast.Call) and call_name(child) == "float") or isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Div):
                    detail = "float or division result enters a payload that is later sealed"
                    findings.append(source_finding(context, self.contract.name, node, detail, "Direct non-exact arithmetic is inside the deterministic serialization path."))
        for loop in (node for node in ast.walk(tree) if isinstance(node, ast.For)):
            unordered = (
                isinstance(loop.iter, (ast.Set, ast.Dict))
                or isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Name) and loop.iter.func.id == "set"
                or isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Attribute) and loop.iter.func.attr in {"items", "keys", "values"}
            )
            writes_payload = any(
                isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in sealed_payloads
                for node in ast.walk(loop)
            )
            if unordered and writes_payload:
                detail = "unordered set/dict iteration contributes to a payload that is later sealed"
                findings.append(source_finding(context, self.contract.name, loop, detail, "Unordered iteration can alter the bytes supplied to the deterministic seal."))
        return tuple(findings)
