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


def _param_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = function.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _cursor_root_is_external(function: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    """True if ``call`` runs against a cursor this function obtained from a
    connection object it did not create itself — i.e. ``with <param>.cursor()
    as cur: cur.execute(...)`` where ``<param>`` is a function parameter.

    Transaction state (autocommit, commit/rollback) lives on the *connection*,
    not the cursor a `with <conn>.cursor()` block merely scopes for cleanup.
    When that connection is caller-supplied, whether a transaction wraps this
    call is a property of the caller this contract cannot see — per its own
    stated scope (forge/skills/_common.py: "must return UNDETERMINED/declare
    a limitation rather than infer... interprocedural behaviour it cannot
    prove"). This does not suppress the finding — a caller-supplied
    connection is exactly as plausibly unwrapped as any other case, and
    silently discarding it would trade a false positive for a false negative
    — it only makes the finding's own claim honest about what it can and
    cannot see, instead of asserting "no visible transaction boundary" as if
    that settled a question this contract has no visibility into.
    """
    if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
        return False
    cursor_name = call.func.value.id
    params = _param_names(function)
    if cursor_name in params:
        return False  # covered by the direct bare-parameter case; not this cursor-scoping case
    for node in ast.walk(function):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            if not (isinstance(item.optional_vars, ast.Name) and item.optional_vars.id == cursor_name):
                continue
            context = item.context_expr
            if (
                isinstance(context, ast.Call)
                and isinstance(context.func, ast.Attribute)
                and context.func.attr == "cursor"
                and isinstance(context.func.value, ast.Name)
                and context.func.value.id in params
            ):
                return True
    return False


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
            external_connection = any(_cursor_root_is_external(function, call) for call, _table in writes)
            if external_connection:
                detail = (
                    "related SQL mutations run through a cursor scoped from a caller-supplied "
                    "connection, with no transaction boundary visible in this function"
                )
                reasoning = (
                    "The connection's transaction state (autocommit, commit/rollback) is owned "
                    "by whoever created it; this contract only inspects this function's own body "
                    "and cannot see whether the caller already wraps this call in a transaction. "
                    "A crash between related writes leaves persistent state only partially "
                    "mutated if the caller does not — verify at the call site(s)."
                )
            else:
                detail = "related SQL mutations occur without a visible transaction boundary"
                reasoning = "A crash between related writes can leave persistent state only partially mutated."
            findings.append(source_finding(context, self.contract.name, writes[0][0], detail, reasoning))
        return tuple(findings)
