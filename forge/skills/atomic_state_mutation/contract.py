"""Direct SQL transaction-boundary contract."""
from __future__ import annotations

import ast
import re

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import ancestors, call_name, live_python, parent_map, parse, source_finding

_MUTATION = re.compile(r"^\s*(INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
_TABLE = re.compile(r"\b(?:INTO|UPDATE|FROM)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)


def _sql(call: ast.Call) -> str | None:
    return call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str) else None


def _related(tables: list[str]) -> bool:
    normalized = [name.rstrip("s").split("_")[0] for name in tables]
    return len(set(normalized)) < len(normalized)


class AtomicStateMutationSkill:
    contract = SkillContract(
        "atomic-state-mutation", "1.0",
        ("related multi-write SQL mutations are bounded by one visible transaction",),
        ("two related INSERT/UPDATE/DELETE statements in one function",),
        ("AST source locations of mutations and transaction context",),
        ("direct SQL string and lexical transaction recognition only; ORM calls and cross-function transactions are undetermined",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        return live_python(context, ".execute(" in context.source or ".executemany(" in context.source)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        parents = parent_map(tree)
        findings = []
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            writes: list[tuple[ast.Call, str]] = []
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}):
                sql = _sql(call)
                if sql and _MUTATION.match(sql):
                    table = _TABLE.search(sql)
                    writes.append((call, table.group(1).lower() if table else ""))
            if len(writes) < 2 or not _related([table for _call, table in writes if table]):
                continue
            protected = any(
                isinstance(parent, ast.With) and any(
                    isinstance(item.context_expr, ast.Name) or (isinstance(item.context_expr, ast.Attribute) and item.context_expr.attr in {"transaction", "atomic"})
                    for item in parent.items
                )
                for parent in ancestors(writes[0][0], parents)
            )
            lexical = ast.get_source_segment(context.source, function) or ""
            protected = protected or bool(re.search(r"\b(?:BEGIN|commit\s*\(|rollback\s*\()", lexical, re.IGNORECASE))
            if protected:
                continue
            detail = "related SQL mutations occur without a visible transaction boundary"
            findings.append(source_finding(context, self.contract.name, writes[0][0], detail, "A crash between related writes can leave persistent state only partially mutated."))
        return tuple(findings)
