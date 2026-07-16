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

_CRED = re.compile(r"(password|passwd|secret|token|api[_-]?key|credential)", re.I)
_PLACEHOLDER = re.compile(r"^(changeme|change_me|example|placeholder|your[_ -].*|<.*>)$", re.I)

def _is_getenv_call(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "getenv"

def _assigned(tree):
    for n in ast.walk(tree):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AnnAssign) else []
        value = getattr(n, "value", None)
        for target in targets:
            if isinstance(target, ast.Name) and _CRED.search(target.id) and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value and not _PLACEHOLDER.match(value.value):
                yield SecurityFinding("hardcoded-credential", "", n.lineno, f"non-empty credential-like string assigned to {target.id}")

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


def _deserialization(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute) or not isinstance(n.func.value, ast.Name): continue
        mod, name = n.func.value.id, n.func.attr
        if (mod, name) in {("pickle", "loads"), ("pickle", "load"), ("marshal", "loads")}:
            yield SecurityFinding("unsafe-deserialization", "", n.lineno, f"{mod}.{name} accepts serialized data without a safe structural boundary")
        elif mod == "yaml" and name == "load":
            safe = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and isinstance(k.value.value, ast.Name) and k.value.value.id == "yaml" and k.value.attr == "SafeLoader" for k in n.keywords)
            if not safe: yield SecurityFinding("unsafe-deserialization", "", n.lineno, "yaml.load lacks Loader=yaml.SafeLoader")

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
        params = {argument.arg for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)}
        normalized = {
            target.id
            for node in ast.walk(function)
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in {"normpath", "realpath"}
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for node in ast.walk(function):
            if enclosing_function(node) is not function or not isinstance(node, ast.Call) or not node.args:
                continue
            reaches_parameter = any(isinstance(argument, ast.Name) and argument.id in params and argument.id not in normalized for argument in node.args)
            if not reaches_parameter:
                continue
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "path":
                yield SecurityFinding("path-traversal", "", node.lineno, "parameter reaches os.path operation without proven normalization")
            elif isinstance(node.func, ast.Name) and node.func.id == "open":
                yield SecurityFinding("path-traversal", "", node.lineno, "parameter reaches open() without proven normalization")

def audit(root: str | os.PathLike[str], eligible: set[str] | None = None) -> tuple[SecurityFinding, ...]:
    base=Path(root)
    scope = set(eligible) if eligible is not None else {m.path for m in triage(base).modules if m.module_class in {ModuleClass.CONNECTED_ALIVE, ModuleClass.FOSSIL_HIGH_RISK, ModuleClass.DEAD_WEIGHT}}
    scan=prepare_python_scan(base, scope); out=[]; examinations=dict(scan.examinations)
    for rel, tree in scan.modules:
        for f in (*_assigned(tree), *_getenv_default_credential(tree), *_unverified_webhooks(tree), *_deserialization(tree), *_paths(tree)): out.append(SecurityFinding(f.family, rel, f.line, f.description))
        examinations[rel]="examined_with_findings" if any(x.path == rel for x in out) else "examined_clean"
    return AgentScanResult(
        tuple(out), examinations,
        mandatory_protocol(
            "security_auditor",
            tuple(f"{item.family} observed at {item.path}:{item.line}" for item in out),
            examinations,
        ),
    )
