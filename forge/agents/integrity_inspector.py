"""Determinism and schema-versioning checks, independent of bug hypotheses."""
from __future__ import annotations
import ast, os
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


def _serialization_has_version(call: ast.Call) -> bool:
    data = call.args[0] if call.args else None
    if isinstance(data, ast.Dict):
        return any(isinstance(key, ast.Constant) and key.value in {"schema_version", "version"} for key in data.keys)
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Attribute) and data.func.attr == "to_dict":
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and data.func.id in {"seal_manifest", "canonical_json"}:
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and data.func.id == "dict":
        return any(keyword.arg in {"schema_version", "version", "benchmark_schema_version"} for keyword in data.keywords)
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
        if not any(isinstance(key, ast.Constant) and key.value in {"schema_version", "version", "benchmark_schema_version"}
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


def inspect(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[IntegrityFinding, ...]:
    base=Path(root); records=triage(base).modules
    eligible = set(eligible) if eligible is not None else {m.path for m in records if m.module_class is ModuleClass.CONNECTED_ALIVE}
    # Preserve the standalone detector contract for tiny unit fixtures with no
    # live module at all; a real repository with any live module uses the
    # explicit CONNECTED_ALIVE-only policy below.
    if not eligible: eligible={m.path for m in records}
    scan=prepare_python_scan(base, eligible); out=[]; examinations=dict(scan.examinations)
    for rel, tree in scan.modules:
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        versioned_payload_names = _versioned_payload_names(tree)
        for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            for line in sorted(float_calls_reaching_return(fn)):
                out.append(IntegrityFinding("decision-adjacent-float", rel, line, "non-deterministic arithmetic in a decision-adjacent path"))
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
