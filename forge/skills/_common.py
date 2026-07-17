"""Small AST primitives shared by executable governance contracts.

These helpers intentionally provide only direct, intra-module evidence.  A
contract must return UNDETERMINED/declare a limitation rather than infer alias
or interprocedural behaviour it cannot prove.
"""
from __future__ import annotations

import ast
from typing import Iterable

from forge.models import Applicability, EvaluationContext, Evidence, Finding, ModuleClass


def live_python(context: EvaluationContext, signal: bool) -> Applicability:
    if context.module.module_class is not ModuleClass.CONNECTED_ALIVE:
        return Applicability.NOT_APPLICABLE
    if context.module.language != "Python":
        return Applicability.NOT_APPLICABLE
    try:
        ast.parse(context.source)
    except SyntaxError:
        return Applicability.UNDETERMINED
    return Applicability.APPLICABLE if signal else Applicability.NOT_APPLICABLE


def parse(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def call_name(node: ast.Call) -> str:
    return dotted(node.func)


def source_finding(context: EvaluationContext, skill: str, node: ast.AST, detail: str, reasoning: str) -> Finding:
    return Finding(
        "INFERRED", "PROTOCOL_GAP", context.module.path, detail,
        (Evidence("source", f"{context.module.path}:{getattr(node, 'lineno', 1)}", detail),),
        reasoning, skill, "PROTOCOL_GAP",
    )


def parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> Iterable[ast.AST]:
    current = parents.get(node)
    while current is not None:
        yield current
        current = parents.get(current)


def literal_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
