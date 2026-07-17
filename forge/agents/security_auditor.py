"""AST-only security checks with conservative, family-specific safe criteria."""
from __future__ import annotations
import ast, os, re
from dataclasses import dataclass
from pathlib import Path
from forge.detector.stack import triage
from forge.agents._scan import prepare_python_scan
from forge.models import AgentScanResult, ModuleClass
from forge.agent_protocol import mandatory_protocol

@dataclass(frozen=True)
class SecurityFinding:
    family: str; path: str; line: int; description: str
    controllability: str = "UNDETERMINED"
    exploitability: str = "NOT_ASSESSED"
    column: int | None = None

_CRED = re.compile(r"(password|passwd|secret|token|api[_-]?key|credential)", re.I)
_PLACEHOLDER = re.compile(r"^(changeme|change_me|example|placeholder|your[_ -].*|<.*>)$", re.I)
_SUBPROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}
_SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}

def _is_getenv_call(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "getenv"

def _credential_target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
        return target.slice.value
    return None


def _is_non_placeholder_credential_literal(value: ast.AST) -> bool:
    return (
        isinstance(value, ast.Constant) and isinstance(value.value, str)
        and bool(value.value) and not _PLACEHOLDER.match(value.value)
    )


def _assigned(tree):
    for n in ast.walk(tree):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AnnAssign) else []
        value = getattr(n, "value", None)
        for target in targets:
            name = _credential_target_name(target)
            if name and _CRED.search(name) and _is_non_placeholder_credential_literal(value):
                yield SecurityFinding("hardcoded-credential", "", n.lineno, f"non-empty credential-like string assigned to {name}")
        if isinstance(n, ast.Dict):
            for key, value in zip(n.keys, n.values):
                if (
                    isinstance(key, ast.Constant) and isinstance(key.value, str)
                    and _CRED.search(key.value) and _is_non_placeholder_credential_literal(value)
                ):
                    yield SecurityFinding("hardcoded-credential", "", n.lineno, f"non-empty credential-like string stored under {key.value!r}")

def _getenv_default_credential(tree):
    """os.getenv(name, default) where default is a hardcoded credential.

    An env var lookup is a legitimate way to source a credential, but a
    non-empty, non-placeholder literal as its *default* argument is a
    credential that silently applies whenever the variable is unset -
    exactly as real a hardcoded secret as a bare assignment, just one
    argument deeper. `_assigned` above cannot see this: its value is an
    ast.Call (the getenv call), not an ast.Constant, so it never matches.
    """
    for node in ast.walk(tree):
        if not (_is_getenv_call(node) and len(node.args) >= 2):
            continue
        default = node.args[1]
        if not (isinstance(default, ast.Constant) and isinstance(default.value, str) and default.value and not _PLACEHOLDER.match(default.value)):
            continue
        name_arg = node.args[0]
        env_name = name_arg.value if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str) else ""
        if _CRED.search(env_name):
            yield SecurityFinding("hardcoded-credential", "", node.lineno, f"os.getenv default value for {env_name!r} is a non-empty hardcoded credential")

_WEBHOOK_PATH = re.compile(r"webhook", re.I)
_SIGNATURE_VERIFICATION = re.compile(r"\b(hmac|signature|verify_signature|compare_digest)\b", re.I)
_MUTATING_HTTP_METHODS = {"post", "put", "patch", "delete"}


def _route_decorators(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield (http_method, path) for @app.<method>("path")-style route decorators."""
    for decorator in function.decorator_list:
        if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in _MUTATING_HTTP_METHODS and decorator.args
                and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)):
            yield decorator.func.attr, decorator.args[0].value


def _has_depends_parameter(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    def is_depends_call(node):
        return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Depends"
    positional = function.args.posonlyargs + function.args.args
    paired_defaults = list(zip(positional[len(positional) - len(function.args.defaults):], function.args.defaults))
    if any(is_depends_call(default) for _, default in paired_defaults):
        return True
    return any(default is not None and is_depends_call(default) for default in function.args.kw_defaults)


def _unverified_webhooks(tree):
    """A route named like a webhook (an external system's callback) that
    mutates state (POST/PUT/PATCH/DELETE) with no FastAPI Depends(...)
    parameter and no signature/HMAC verification anywhere in its own body.

    Scoped to the "webhook" naming convention deliberately: a generic
    "no Depends()" check would flag every intentionally public endpoint
    (checkout, cart) that this project's own design makes public by choice.
    A webhook is different - it claims to be an authoritative callback from
    an external system (a payment provider), which conventionally requires
    verifying the caller really is that system (a shared-secret signature),
    not just accepting whatever a request body claims.
    """
    for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        for method, path in _route_decorators(function):
            if not _WEBHOOK_PATH.search(path):
                continue
            if _has_depends_parameter(function):
                continue
            body_source = ast.unparse(function)
            if _SIGNATURE_VERIFICATION.search(body_source):
                continue
            yield SecurityFinding("unverified-webhook", "", function.lineno, f"{method.upper()} route {path!r} has no auth dependency and no signature/HMAC verification in its body")


def _module_import_aliases(tree: ast.Module) -> dict[str, str]:
    """Resolve only unambiguous, module-level spellings of risky imports."""
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name in {"pickle", "marshal", "yaml"}:
                    aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"pickle", "marshal", "yaml"}:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _function_shadows_name(function: ast.FunctionDef | ast.AsyncFunctionDef | None, name: str) -> bool:
    """Avoid treating a module import as authoritative after a local shadow."""
    if function is None:
        return False
    parameters = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    if any(parameter.arg == name for parameter in parameters):
        return True
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return True
    return False


def _deserialization(tree: ast.Module):
    aliases = _module_import_aliases(tree)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def enclosing_function(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current = parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parents.get(current)
        return None

    def canonical_target(node: ast.AST, function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> str | None:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if _function_shadows_name(function, node.value.id):
                return None
            module = aliases.get(node.value.id, node.value.id)
            return f"{module}.{node.attr}" if module in {"pickle", "marshal", "yaml"} else None
        if isinstance(node, ast.Name) and not _function_shadows_name(function, node.id):
            return aliases.get(node.id)
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = canonical_target(node.func, enclosing_function(node))
        if target in {"pickle.loads", "pickle.load", "marshal.loads"}:
            yield SecurityFinding("unsafe-deserialization", "", node.lineno, f"{target} accepts serialized data without a safe structural boundary")
        elif target in {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}:
            safe = any(
                keyword.arg == "Loader" and isinstance(keyword.value, ast.Attribute)
                and keyword.value.attr == "SafeLoader"
                for keyword in node.keywords
            )
            if not safe:
                yield SecurityFinding("unsafe-deserialization", "", node.lineno, f"{target} lacks Loader=yaml.SafeLoader")

def _assignment_target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for item in node.elts for name in _assignment_target_names(item)}
    return set()


def _is_path_sanitizer(value: ast.AST) -> bool:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value.func.attr in {"normpath", "realpath", "basename", "resolve"}:
            return True
    return isinstance(value, ast.Attribute) and value.attr == "name"


def _path_barrier_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, int]:
    """Return names proven sanitized before a later sink in one function."""
    barriers: dict[str, int] = {}

    # Fixed point is deliberate: `b = basename(a); c = b; open(c)` is just as
    # safe as using b directly, and a one-pass AST walk loses that fact.
    changed = True
    while changed:
        changed = False
        for node in ast.walk(function):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            safe = _is_path_sanitizer(value) or any(
                isinstance(name, ast.Name) and name.id in barriers
                for name in ast.walk(value) if isinstance(name, ast.Name)
            )
            if safe:
                for target in targets:
                    for name in _assignment_target_names(target):
                        if name not in barriers:
                            barriers[name] = node.lineno
                            changed = True
    # Validation barriers only apply after their guard.  The body must visibly
    # terminate, otherwise an allowlist/extension check is merely commentary.
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not any(isinstance(item, (ast.Raise, ast.Return)) for item in ast.walk(node)):
            continue
        names = {item.id for item in ast.walk(node.test) if isinstance(item, ast.Name)}
        allowlist = isinstance(node.test, ast.Compare) and any(isinstance(op, (ast.NotIn, ast.In)) for op in node.test.ops)
        extension = any(isinstance(item, ast.Attribute) and item.attr in {"endswith", "suffix"} for item in ast.walk(node.test))
        if allowlist or extension:
            for name in names:
                barriers.setdefault(name, node.lineno)
    return barriers


def _literal_or_constant_path(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path"
        and any(isinstance(item, ast.Name) and item.id == "__file__" for item in ast.walk(node))
    )


def _path_controllability(
    tree: ast.AST, function: ast.FunctionDef | ast.AsyncFunctionDef, parameter: str,
) -> str:
    params = [item.arg for item in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)]
    if parameter not in params:
        return "UNDETERMINED"
    if any(True for _ in _route_decorators(function)) or function.name == "analyze":
        return "ATTACKER_CONTROLLED"
    if not function.name.startswith("_"):
        return "UNDETERMINED"
    index = params.index(parameter)
    callers = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == function.name
    ]
    if callers and all(index < len(call.args) and _literal_or_constant_path(call.args[index]) for call in callers):
        return "INTERNAL_ONLY"
    return "UNDETERMINED"


def _function_parameter_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {argument.arg for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)}


def _unsafe_param_origins(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    calls: tuple[ast.Call, ...],
    enclosing_function,
    is_sanitizer,
    barriers: dict[str, int] | None = None,
) -> dict[ast.Call, dict[str, set[str]]]:
    """Compute local unsafe origins once, then snapshot them at each call.

    The caller supplies family policy through ``is_sanitizer`` and optional
    line-scoped barriers. Assignments are processed in source order, so one
    graph serves path, SQL, and command sinks without per-sink AST walks.
    """
    unsafe = {name: {name} for name in _function_parameter_names(function)}
    assignments = sorted(
        (
            node for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and enclosing_function(node) is function
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    barrier_items = sorted(
        (barriers or {}).items(), key=lambda item: (item[1], item[0])
    )
    snapshots: dict[ast.Call, dict[str, set[str]]] = {}
    assignment_index = barrier_index = 0

    for call in sorted(calls, key=lambda node: (node.lineno, node.col_offset)):
        call_position = (call.lineno, call.col_offset)
        while assignment_index < len(assignments):
            assignment = assignments[assignment_index]
            if (assignment.lineno, assignment.col_offset) > call_position:
                break
            assignment_index += 1
            targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            if is_sanitizer(assignment.value):
                origins: set[str] = set()
            else:
                origins = set().union(*(
                    unsafe.get(name.id, set())
                    for name in ast.walk(assignment.value)
                    if isinstance(name, ast.Name)
                ))
            for target in targets:
                for name in _assignment_target_names(target):
                    if origins:
                        unsafe[name] = set(origins)
                    else:
                        unsafe.pop(name, None)
        while barrier_index < len(barrier_items) and barrier_items[barrier_index][1] <= call.lineno:
            name, _line = barrier_items[barrier_index]
            unsafe.pop(name, None)
            barrier_index += 1
        snapshots[call] = {name: set(origins) for name, origins in unsafe.items()}
    return snapshots


def _origins_reaching(argument: ast.AST, unsafe: dict[str, set[str]], is_sanitizer) -> set[str]:
    """Return unsafe origins reaching an expression outside family barriers."""
    protected: set[ast.AST] = set()
    for node in ast.walk(argument):
        if is_sanitizer(node):
            protected.update(ast.walk(node))
        # A value used only as a mapping key/index is not itself the path that
        # reaches the sink: `open(config.get(user_path))` opens the configured
        # value, while `open(user_path.get("name"))` still exposes user_path as
        # the container and remains observable below.
        if isinstance(node, ast.Subscript):
            protected.update(ast.walk(node.slice))
        elif (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"get", "pop"}
        ):
            for key in (*node.args, *(keyword.value for keyword in node.keywords)):
                protected.update(ast.walk(key))
    origins: set[str] = set()
    for node in ast.walk(argument):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node not in protected:
            origins.update(unsafe.get(node.id, set()))
    return origins


def _path_flow_at_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    calls: tuple[ast.Call, ...],
    enclosing_function,
) -> dict[ast.Call, dict[str, set[str]]]:
    """Path-policy wrapper around the shared intra-function flow engine."""
    return _unsafe_param_origins(
        function, calls, enclosing_function, _is_path_sanitizer, _path_barrier_names(function),
    )


def _unsafe_origins_in_path_expression(argument: ast.AST, unsafe: dict[str, set[str]]) -> set[str]:
    return _origins_reaching(argument, unsafe, _is_path_sanitizer)


def _no_sanitizer(_value: ast.AST) -> bool:
    return False


def _sql_injection(tree: ast.AST):
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def enclosing_function(node):
        current = parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parents.get(current)
        return None

    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        calls = tuple(
            node for node in ast.walk(function)
            if enclosing_function(node) is function and isinstance(node, ast.Call)
        )
        flows = _unsafe_param_origins(function, calls, enclosing_function, _no_sanitizer)
        for node in calls:
            if not (
                isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_EXEC_METHODS and node.args
            ):
                continue
            query = node.args[0]
            origins = _origins_reaching(query, flows[node], _no_sanitizer)
            if origins and not isinstance(query, ast.Constant):
                control = _path_controllability(tree, function, sorted(origins)[0])
                yield SecurityFinding("sql-injection", "", node.lineno, "unsafe SQL interpolation reaches execute() without parameter binding", control, "PLAUSIBLE")


def _is_command_sanitizer(value: ast.AST) -> bool:
    return (
        isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
        and isinstance(value.func.value, ast.Name) and value.func.value.id == "shlex"
        and value.func.attr == "quote"
    )


def _has_literal_shell_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in node.keywords
    )


def _command_injection(tree: ast.AST):
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def enclosing_function(node):
        current = parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parents.get(current)
        return None

    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        calls = tuple(
            node for node in ast.walk(function)
            if enclosing_function(node) is function and isinstance(node, ast.Call)
        )
        flows = _unsafe_param_origins(function, calls, enclosing_function, _is_command_sanitizer)
        for node in calls:
            if not node.args:
                continue
            command = node.args[0]
            origins = _origins_reaching(command, flows[node], _is_command_sanitizer)
            if not origins or isinstance(command, (ast.Constant, ast.List, ast.Tuple)):
                continue
            is_os_shell = (
                isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os" and node.func.attr in {"system", "popen"}
            )
            is_subprocess_shell = (
                isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess" and node.func.attr in _SUBPROCESS_CALLS
                and _has_literal_shell_true(node)
            )
            if not (is_os_shell or is_subprocess_shell):
                continue
            control = _path_controllability(tree, function, sorted(origins)[0])
            sink = f"os.{node.func.attr}" if is_os_shell else "subprocess shell=True"
            yield SecurityFinding("command-injection", "", node.lineno, f"unsafe command interpolation reaches {sink}", control, "PLAUSIBLE")


def _paths(tree):
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def enclosing_function(node):
        current = parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parents.get(current)
        return None

    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        calls = tuple(
            node for node in ast.walk(function)
            if enclosing_function(node) is function and isinstance(node, ast.Call)
        )
        flows = _path_flow_at_calls(function, calls, enclosing_function)
        for node in calls:
            arguments = (*node.args, *(keyword.value for keyword in node.keywords))
            unsafe = flows[node]
            origins = set().union(*(
                _unsafe_origins_in_path_expression(argument, unsafe) for argument in arguments
            ))
            if not origins:
                continue
            controllability = _path_controllability(tree, function, sorted(origins)[0])
            is_os_path_operation = (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "os"
                and node.func.value.attr == "path"
                and node.func.attr not in {"normpath", "realpath", "basename", "resolve"}
            )
            if is_os_path_operation:
                yield SecurityFinding("path-traversal", "", node.lineno, "parameter reaches os.path operation without proven normalization", controllability, "PLAUSIBLE", node.col_offset + 1)
            elif isinstance(node.func, ast.Name) and node.func.id == "open":
                yield SecurityFinding("path-traversal", "", node.lineno, "parameter reaches open() without proven normalization", controllability, "PLAUSIBLE", node.col_offset + 1)

def audit(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[SecurityFinding, ...]:
    base=Path(root)
    scope = set(eligible) if eligible is not None else {m.path for m in triage(base).modules if m.module_class in {ModuleClass.CONNECTED_ALIVE, ModuleClass.FOSSIL_HIGH_RISK, ModuleClass.DEAD_WEIGHT}}
    scan=prepare_python_scan(base, scope); out=[]; examinations=dict(scan.examinations)
    for rel, tree in scan.modules:
        for f in (*_assigned(tree), *_getenv_default_credential(tree), *_unverified_webhooks(tree), *_deserialization(tree), *_paths(tree), *_sql_injection(tree), *_command_injection(tree)):
            out.append(SecurityFinding(f.family, rel, f.line, f.description, f.controllability, f.exploitability, f.column))
        examinations[rel]="examined_with_findings" if any(x.path == rel for x in out) else "examined_clean"
    return AgentScanResult(
        tuple(out), examinations,
        mandatory_protocol(
            "security_auditor",
            tuple(f"{item.family} observed at {item.path}:{item.line}" for item in out),
            examinations,
        ),
    )
