"""Determinism and schema-versioning checks, independent of bug hypotheses."""
from __future__ import annotations
import ast, os, re
from dataclasses import dataclass
from pathlib import Path
from forge.detector.stack import triage
from forge.agents._scan import prepare_python_scan
from forge.dataflow import float_calls_reaching_return
from forge.models import AgentScanResult, ModuleClass
from forge.agent_protocol import mandatory_protocol

@dataclass(frozen=True)
class IntegrityFinding:
    family: str; path: str; line: int; description: str

_MONEY_NAME = re.compile(r"(price|cost|amount|total|subtotal|discount|fee|balance|charge|payment)", re.I)
_SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}


def _sql_real_money_columns(tree: ast.AST) -> list[tuple[int, str]]:
    """Line numbers of CREATE TABLE column definitions declaring a
    money-shaped column REAL (SQLite's floating-point type)."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_EXEC_METHODS):
            continue
        for arg in node.args:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "CREATE TABLE" in arg.value.upper()):
                continue
            for match in re.finditer(r"(\w+)\s+REAL\b", arg.value, re.I):
                if _MONEY_NAME.search(match.group(1)):
                    hits.append((node.lineno, match.group(1)))
    return hits


def _money_shaped(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        return bool(_MONEY_NAME.search(node.slice.value))
    if isinstance(node, ast.Attribute):
        return bool(_MONEY_NAME.search(node.attr))
    if isinstance(node, ast.Name):
        return bool(_MONEY_NAME.search(node.id))
    return False


def _money_float_division_lines(tree: ast.AST) -> set[int]:
    """Lines where round() wraps a true division (`/`) touching a
    money-shaped name, without ever calling float() explicitly.

    `/` always produces a float in Python 3 regardless of operand types, so
    a SQLite REAL column or an int divided this way silently becomes a
    float here - decision-adjacent-float never sees it because there is no
    float() call for float_calls_reaching_return to trace.
    """
    hits: set[int] = set()
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "round" and call.args):
            continue
        for node in ast.walk(call.args[0]):
            if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)):
                continue
            if any(_money_shaped(side) for side in ast.walk(node) if isinstance(side, (ast.Subscript, ast.Attribute, ast.Name))):
                hits.add(call.lineno)
                break
    return hits


def _is_version_key(name: object) -> bool:
    """Recognize the project-wide `<domain>_schema_version` naming
    convention structurally instead of an enumerated allowlist.

    The codebase has at least ten of these (schema_version,
    findings_jsonl_schema_version, metrics_schema_version,
    profile_schema_version, sharding_schema_version,
    comparison_schema_version, hypotheses_schema_version,
    benchmark_schema_version, precision_schema_version,
    loop_schema_version, ...) - one per artifact type, and a new artifact
    adds another. An exact-match set silently misses every one it was not
    updated for, which is exactly the class of self-inflicted false
    positive an enumerated list produces as the codebase grows.
    """
    return isinstance(name, str) and (name == "version" or name.endswith("schema_version"))


_VERSIONING_TRUSTED_CALLS = {"seal_manifest", "seal_findings", "canonical_json"}


def _serialization_has_version(call: ast.Call) -> bool:
    data = call.args[0] if call.args else None
    if isinstance(data, ast.Dict):
        return any(isinstance(key, ast.Constant) and _is_version_key(key.value) for key in data.keys)
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Attribute) and data.func.attr == "to_dict":
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and data.func.id in _VERSIONING_TRUSTED_CALLS:
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and data.func.id == "dict":
        return any(_is_version_key(keyword.arg) for keyword in data.keywords)
    return False


def _versioned_payload_names(tree: ast.AST) -> set[str]:
    """Find simple local names bound to dicts carrying a schema/version key."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Dict):
            continue
        if not any(isinstance(key, ast.Constant) and _is_version_key(key.value)
                   for key in value.keys):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def _is_internal_serialization(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    current = parents.get(call)
    while current is not None:
        if isinstance(current, ast.Call) and (
            (isinstance(current.func, ast.Name) and current.func.id == "print")
            or (isinstance(current.func, ast.Attribute) and current.func.attr in {"debug", "info", "warning", "error", "exception", "critical"})
        ):
            return True
        current = parents.get(current)
    return False


def _is_presentation_serialization(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """Recognize serialization embedded in a presentation template structurally."""
    current = parents.get(call)
    while current is not None:
        if isinstance(current, ast.JoinedStr):
            return True
        current = parents.get(current)
    return False


def _enclosing_function(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    current = parents.get(call)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parents.get(current)
    return ""


def inspect(root: str | os.PathLike[str], eligible: set[str] | None = None, ml_domain_paths: frozenset[str] | None = None) -> tuple[IntegrityFinding, ...]:
    base=Path(root); records=triage(base).modules
    eligible = set(eligible) if eligible is not None else {m.path for m in records if m.module_class is ModuleClass.CONNECTED_ALIVE}
    # Preserve the standalone detector contract for tiny unit fixtures with no
    # live module at all; a real repository with any live module uses the
    # explicit CONNECTED_ALIVE-only policy below.
    if not eligible: eligible={m.path for m in records}
    ml_domain_paths = ml_domain_paths or frozenset()
    scan=prepare_python_scan(base, eligible); out=[]; examinations=dict(scan.examinations)
    for rel, tree in scan.modules:
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        versioned_payload_names = _versioned_payload_names(tree)
        # A module inferred as machine_learning domain (governance.runtime's
        # infer_domains: torch/tensorflow/sklearn/numpy/pandas import) uses
        # float legitimately for numeric computation - model weights,
        # predictions, physical quantities derived from signals. Flagging
        # every float() reaching a return there is exactly the FP-001 class
        # of mistake (proxy signal instead of a real decision/verdict path),
        # just triggered by domain instead of by naming proximity. The
        # module is still examined and still checked for the other
        # families below.
        if rel not in ml_domain_paths:
            for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
                for line in sorted(float_calls_reaching_return(fn)):
                    out.append(IntegrityFinding("decision-adjacent-float", rel, line, "non-deterministic arithmetic in a decision-adjacent path"))
        # Money as float: the value is float-typed by provenance (a SQLite
        # REAL column, or `/` true division) rather than by an explicit
        # float() call, so decision-adjacent-float's call-site tracing
        # cannot see it at all. Independent of ml_domain_paths - this is
        # about money, never about model/signal computation.
        for line, column in _sql_real_money_columns(tree):
            out.append(IntegrityFinding("money-as-float", rel, line, f"money-shaped column '{column}' declared REAL (SQLite floating-point) instead of an integer/cents type"))
        for line in sorted(_money_float_division_lines(tree)):
            out.append(IntegrityFinding("money-as-float", rel, line, "round() over a floating-point division touching a money-shaped value; no explicit float() call, so it bypasses decision-adjacent-float"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"dump", "dumps"} and isinstance(n.func.value, ast.Name) and n.func.value.id in {"json","pickle"}:
                if (_is_internal_serialization(n, parents) or _is_presentation_serialization(n, parents)
                        or _serialization_has_version(n)
                        or (isinstance(n.args[0], ast.Name) and n.args[0].id in versioned_payload_names)):
                    continue
                out.append(IntegrityFinding("unversioned-serialization", rel, n.lineno, "unversioned serialization"))
        examinations[rel]="examined_with_findings" if any(x.path == rel for x in out) else "examined_clean"
    return AgentScanResult(
        tuple(out), examinations,
        mandatory_protocol(
            "integrity_inspector",
            tuple(f"{item.family} observed at {item.path}:{item.line}" for item in out),
            examinations,
        ),
    )
