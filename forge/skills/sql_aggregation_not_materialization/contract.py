"""Detect direct SQL materialization and N+1 shapes with explicit guards."""
from __future__ import annotations

import ast

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import ancestors, call_name, live_python, parent_map, parse, source_finding


def _fetchall(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "fetchall"


class SqlAggregationNotMaterializationSkill:
    contract = SkillContract(
        "sql-aggregation-not-materialization", "1.0",
        ("counting/aggregation stays in SQL and hot paths avoid direct N+1 queries",),
        ("len(fetchall())", "execute inside an application loop"),
        ("AST source evidence of the materialization or loop",),
        ("cannot establish call frequency or ORM semantics; setup/migration functions are excluded by name",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        return live_python(context, ".execute(" in context.source or ".fetchall(" in context.source)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        parents = parent_map(tree)
        findings = []
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if isinstance(call.func, ast.Name) and call.func.id == "len" and call.args and _fetchall(call.args[0]):
                detail = "len(fetchall()) materializes rows only to count them instead of using SQL COUNT(*)"
                findings.append(source_finding(context, self.contract.name, call, detail, "The database can compute the aggregate without transferring every row."))
            if not (isinstance(call.func, ast.Attribute) and call.func.attr in {"execute", "executemany"}):
                continue
            container = next((parent for parent in ancestors(call, parents) if isinstance(parent, (ast.For, ast.While))), None)
            if container is None:
                continue
            function = next((parent for parent in ancestors(call, parents) if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
            if function and any(token in function.name.lower() for token in ("migrat", "setup", "bootstrap", "seed")):
                continue  # FP guard: deliberate one-time setup is not assumed hot.
            detail = "SQL execute occurs inside an application loop (potential N+1 query pattern)"
            findings.append(source_finding(context, self.contract.name, call, detail, "A batched query or preload should be considered before issuing one query per loop item."))
        return tuple(findings)
