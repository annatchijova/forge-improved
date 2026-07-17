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


def _sql_real_money_columns(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Money-shaped SQL columns using a floating or ambiguous numeric type."""
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_EXEC_METHODS):
            continue
        for arg in node.args:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "CREATE TABLE" in arg.value.upper()):
                continue
            for match in re.finditer(r"(\w+)\s+(REAL|FLOAT|DOUBLE|NUMERIC)\b", arg.value, re.I):
                if _MONEY_NAME.search(match.group(1)):
                    hits.append((node.lineno, match.group(1), match.group(2).upper()))
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
    """Lines with a true division (`/`) touching a money-shaped name.

    `/` always produces a float in Python 3 regardless of operand types, so
    a SQLite REAL column or an int divided this way silently becomes a
    float here - decision-adjacent-float never sees it because there is no
    float() call for float_calls_reaching_return to trace.
    """
    hits: set[int] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)):
            continue
        if any(_money_shaped(side) for side in ast.walk(node) if isinstance(side, (ast.Subscript, ast.Attribute, ast.Name))):
            hits.add(node.lineno)
    return hits


def _money_float_literal_lines(tree: ast.AST) -> set[int]:
    """Assignments of a binary float literal to a money-shaped name."""
    hits: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, float):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(_money_shaped(target) for target in targets):
            hits.add(node.lineno)
    return hits


def _is_version_key(name: object) -> bool:
    """Recognize the project-wide `<domain>_schema_version` naming
    convention structurally instead of an enumerated allowlist.

    The codebase has at least ten of these (schema_version,
    findings_jsonl_schema_version, metrics_schema_version,
    profile_schema_version, sharding_schema_version,
    comparison_schema_version, hypotheses_schema_version,
    benchmark_schema_version, precision_schema_version,
    loop_schema_version, trace_version, ...) - one per artifact type, and a
    new artifact adds another. An exact-match set silently misses every one
    it was not updated for, which is exactly the class of self-inflicted
    false positive an enumerated list produces as the codebase grows. Any
    "_version" suffix counts, not just "_schema_version" specifically -
    trace_version (forge/multi_agent.py) follows the same convention
    without the word "schema".
    """
    return isinstance(name, str) and (name == "version" or name.endswith("_version"))


_VERSIONING_TRUSTED_NAMES = {"seal_manifest", "seal_findings"}


def _is_trusted_versioning_name(name: str) -> bool:
    """A trusted deterministic-serialization primitive, structurally.

    `canonical_json` was the one enumerated name; `canonical_findings_bytes`
    (forge/tiered_report.py) is the identical pattern under the project's
    own "canonical_*" naming convention and was missed the same way the
    schema_version-key allowlist was - matched by prefix, not by adding a
    second name to another exact-match set.
    """
    return name in _VERSIONING_TRUSTED_NAMES or name.startswith("canonical_")


def _serialization_has_version(call: ast.Call) -> bool:
    data = call.args[0] if call.args else None
    if isinstance(data, ast.Dict):
        return any(isinstance(key, ast.Constant) and _is_version_key(key.value) for key in data.keys)
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Attribute) and data.func.attr == "to_dict":
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and _is_trusted_versioning_name(data.func.id):
        return True
    if isinstance(data, ast.Call) and isinstance(data.func, ast.Name) and data.func.id == "dict":
        return any(_is_version_key(keyword.arg) for keyword in data.keywords)
    return False


def _versioned_producer_functions(modules: list[tuple[str, ast.AST]]) -> set[str]:
    """Function names, anywhere in the audited scope, whose body returns a
    versioned payload - directly (a dict literal carrying a version key) or
    transitively (`return other_producer(...)`, e.g. `load_and_validate`
    returning `validate_independent_results(...)`'s already-versioned dict).

    A local variable assigned from a call to one of these (`metrics =
    collect_metrics(...)`, a `profile` parameter passed in from
    `build_repository_profile(...)`, `comparison = compare_runs(...)`) is
    versioned exactly the same as a literal dict assignment is - the
    version key is just one function call away, in a different file.
    Computed once, structurally, over whatever is in scope: no enumerated
    list of "known FORGE functions" to maintain as new ones are added.
    """
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for _, tree in modules:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(node.name, node)
    producers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, node in functions.items():
            if name in producers:
                continue
            for stmt in ast.walk(node):
                if not (isinstance(stmt, ast.Return) and stmt.value is not None):
                    continue
                if isinstance(stmt.value, ast.Dict) and any(isinstance(key, ast.Constant) and _is_version_key(key.value) for key in stmt.value.keys):
                    producers.add(name); changed = True; break
                if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id in producers:
                    producers.add(name); changed = True; break
    return producers


def _versioned_payload_names(tree: ast.AST, producer_functions: frozenset[str] = frozenset()) -> set[str]:
    """Find simple local names bound to a versioned payload - a dict
    literal carrying a version key, or a call to a versioned-producer
    function (see `_versioned_producer_functions`)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        target_names = [target.id for target in targets if isinstance(target, ast.Name)]
        if isinstance(value, ast.Dict) and any(isinstance(key, ast.Constant) and _is_version_key(key.value) for key in value.keys):
            names.update(target_names)
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in producer_functions:
            names.update(target_names)
    return names


def _hash_input_names(tree: ast.AST) -> set[str]:
    """Local names assigned from `json.dumps(...)`/`pickle.dumps(...)` whose
    only later use, within the same function, feeds `hashlib.<algo>(...)`.

    This is `canonical_json`'s exemption again (a hashing primitive is not
    itself a persisted artifact needing a version key), for the shape where
    the dump and the hash are two separate statements rather than one
    nested expression: `forge/agent_independence.py::_fingerprint()`
    computes `payload = json.dumps(work, ...)` then
    `hashlib.sha256(payload.encode(...))` two lines later.
    """
    names: set[str] = set()
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        dumped_names: set[str] = set()
        for node in ast.walk(fn):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "dumps"
                    and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id in {"json", "pickle"}):
                dumped_names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        if not dumped_names:
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib"):
                continue
            names.update(inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name) and inner.id in dumped_names)
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


def _is_sql_parameter_binding(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """A json.dumps(...) sitting directly in the parameter tuple of a
    `.execute(sql, params)` / `.executemany(...)` call - one column value in
    an already-versioned database row (a row typically carries its own
    version column, as forge/cronos/store.py's `cronos_version` does), not a
    standalone JSON document.

    Deliberately narrow: only the tuple passed *directly* as a call
    argument, not "any enclosing tuple" - an earlier, broader version of
    this check (any ast.Tuple ancestor) silently suppressed 31 real
    findings elsewhere in the codebase, where a tuple just happens to hold
    an Evidence/Finding field that is a genuine standalone JSON document.
    """
    parent = parents.get(call)
    if not isinstance(parent, ast.Tuple):
        return False
    grandparent = parents.get(parent)
    return (
        isinstance(grandparent, ast.Call) and isinstance(grandparent.func, ast.Attribute)
        and grandparent.func.attr in {"execute", "executemany"} and parent in grandparent.args
    )


def _is_presentation_serialization(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """Recognize serialization embedded in a presentation template structurally.

    Two independent shapes count: interpolation into an f-string
    (ast.JoinedStr), and `html.escape(json.dumps(...))` - the HTML report
    renderers' own convention for embedding a JSON dump as readable text in
    a report page. Found via a self-audit of forge/tiered_report.py, which
    false-flagged five such calls: the dump there is presentation (a human
    reading a report), never a persisted artifact needing its own version
    key, but this check only recognized the f-string shape.
    """
    current = parents.get(call)
    while current is not None:
        if isinstance(current, ast.JoinedStr):
            return True
        if (isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute)
                and current.func.attr == "escape" and isinstance(current.func.value, ast.Name)
                and current.func.value.id == "html"):
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
    producer_functions = frozenset(_versioned_producer_functions(scan.modules))
    for rel, tree in scan.modules:
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        versioned_payload_names = _versioned_payload_names(tree, producer_functions)
        hash_input_names = _hash_input_names(tree)
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
        for line, column, sql_type in _sql_real_money_columns(tree):
            out.append(IntegrityFinding("money-as-float", rel, line, f"money-shaped column '{column}' declared {sql_type} instead of an integer/cents or exact-decimal type"))
        for line in sorted(_money_float_division_lines(tree)):
            out.append(IntegrityFinding("money-as-float", rel, line, "floating-point division touches a money-shaped value; no explicit float() call, so it bypasses decision-adjacent-float"))
        for line in sorted(_money_float_literal_lines(tree)):
            out.append(IntegrityFinding("money-as-float", rel, line, "binary float literal assigned to a money-shaped value"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"dump", "dumps"} and isinstance(n.func.value, ast.Name) and n.func.value.id in {"json","pickle"}:
                assigned_to = parents.get(n)
                assigned_names = (
                    {target.id for target in assigned_to.targets if isinstance(target, ast.Name)}
                    if isinstance(assigned_to, ast.Assign) else set()
                )
                if (_is_internal_serialization(n, parents) or _is_presentation_serialization(n, parents)
                        or _serialization_has_version(n)
                        or (isinstance(n.args[0], ast.Name) and n.args[0].id in versioned_payload_names)
                        or _is_trusted_versioning_name(_enclosing_function(n, parents))
                        or _is_sql_parameter_binding(n, parents)
                        or bool(assigned_names & hash_input_names)):
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
