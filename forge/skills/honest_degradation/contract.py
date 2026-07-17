"""Executable structural subset of skills-gpt/honest-degradation.md."""
from __future__ import annotations

import ast

from forge.models import Applicability, EvaluationContext, SkillContract
from forge.skills._common import call_name, live_python, parse, source_finding


_VISIBILITY_TOKENS = (
    "abstain", "degraded", "discard", "dropped", "error", "failed", "failure",
    "invalid", "limitation", "non_utf8", "skipped", "unanalyzed", "unanalysed", "unparsed",
    "unreadable", "warn", "warning",
)
_VISIBILITY_FUNCTIONS = (
    "abstain", "mark_degraded", "mark_unanalyzed", "mark_unanalysed",
    "record_drop", "record_error", "record_failure", "record_skip", "unanalyzed",
)
_ERROR_ACCUMULATORS = ("errors", "failures", "drops", "dropped", "discarded", "skipped", "unparsed", "limitations")
_STAGE_TOKENS = (
    "artifact", "bundle", "caie", "engine", "metadata", "profile", "result",
    "signal", "stage", "timeline",
)
_STAGE_PREFIXES = ("analyze", "build", "convert", "load", "parse", "process", "run", "to")


def _text(node: ast.AST) -> str:
    try:
        return ast.unparse(node).lower()
    except (AttributeError, ValueError):
        return ""


def _contains_token(node: ast.AST, tokens: tuple[str, ...]) -> bool:
    return any(token in _text(node) for token in tokens)


def _name_has_token(name: str, tokens: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in tokens)


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]):
    current = parents.get(node)
    while current is not None:
        yield current
        current = parents.get(current)


def _nearest_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for ancestor in _ancestors(node, parents):
        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return ancestor
    return None


def _handler_is_in_loop(handler: ast.ExceptHandler, parents: dict[ast.AST, ast.AST]) -> bool:
    return any(isinstance(ancestor, (ast.For, ast.While)) for ancestor in _ancestors(handler, parents))


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {target.id for target in targets if isinstance(target, ast.Name)}


def _is_empty_or_default(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value in {None, False, 0, ""}
    return isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)) and not getattr(node, "elts", getattr(node, "keys", ()))


def _has_visibility_action(body: list[ast.stmt]) -> bool:
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if any(_name_has_token(name, _VISIBILITY_TOKENS) for name in _assigned_names(node)):
                    return True
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(_contains_token(target, _VISIBILITY_TOKENS) for target in targets):
                    return True
                value = node.value
                if value is not None and _contains_token(value, _VISIBILITY_TOKENS):
                    return True
            if isinstance(node, ast.AugAssign):
                # A counter such as ``unparsed += 1`` is a structural F7
                # marker: it makes partial analysis observable in the result.
                if _contains_token(node.target, _VISIBILITY_TOKENS):
                    return True
            if isinstance(node, ast.Call):
                name = call_name(node).lower()
                if any(token in name for token in _VISIBILITY_FUNCTIONS):
                    return True
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "add", "insert"}:
                    receiver = _text(node.func.value)
                    if any(token in receiver for token in _ERROR_ACCUMULATORS):
                        return True
                    if any(_contains_token(arg, _VISIBILITY_TOKENS) for arg in node.args):
                        return True
    return False


def _function_returns_collection_built_in_loop(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    if function is None:
        return False
    collection_names: set[str] = set()
    appended_names: set[str] = set()
    returned_names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Set, ast.Dict)):
            collection_names.update(_assigned_names(node))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "add", "insert"}:
            if isinstance(node.func.value, ast.Name):
                appended_names.add(node.func.value.id)
        if isinstance(node, ast.Return) and node.value is not None:
            returned_names.update(child.id for child in ast.walk(node.value) if isinstance(child, ast.Name))
    return bool(collection_names & appended_names & returned_names)


def _function_is_required_stage(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    if function is None:
        return False
    name = function.name.lower()
    # Prefixes describe whole verb segments, not arbitrary leading letters:
    # ``to_signal`` is a conversion stage while ``token_count`` is not.
    if any(name == prefix or name.startswith(f"{prefix}_") for prefix in _STAGE_PREFIXES):
        return True
    if _name_has_token(name, _STAGE_TOKENS):
        return True
    for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        if _name_has_token(argument.arg, _STAGE_TOKENS):
            return True
    return False


def _try_body_touches_stage(handler: ast.ExceptHandler, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(handler)
    if not isinstance(parent, ast.Try):
        return False
    for stmt in parent.body:
        for node in ast.walk(stmt):
            if isinstance(node, (ast.Name, ast.Attribute, ast.Call)) and _name_has_token(_text(node), _STAGE_TOKENS):
                return True
    return False


def _default_return_values(body: list[ast.stmt]) -> bool:
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Return) and node.value is not None and _is_empty_or_default(node.value):
                return True
            if isinstance(node, ast.Pass):
                return True
    return False


_PARSE_OR_DECODE_EXCEPTIONS = (
    "syntaxerror", "jsondecodeerror", "unicodedecodeerror", "yamlerror",
    "tomldecodeerror",
)


def _handles_specific_parse_or_decode_error(handler: ast.ExceptHandler) -> bool:
    """Return true only for a narrow, explicitly named parse/decode failure.

    This is intentionally independent of the helper name.  A broad
    ``except Exception`` in ``parse_x`` is still a potentially silent fallback;
    conversely, a specifically caught syntax/decode failure is an honest
    not-parseable sentinel even when the function has another name.
    """
    handled = tuple(handler.type.elts) if isinstance(handler.type, ast.Tuple) else ((handler.type,) if handler.type else ())
    if not handled:
        return False
    return all(_text(item).lower().endswith(_PARSE_OR_DECODE_EXCEPTIONS) for item in handled)


def _stage_swallow_targets(handler: ast.ExceptHandler, function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> set[str]:
    if function is None:
        return set()
    targets: set[str] = set()
    for stmt in handler.body:
        for node in ast.walk(stmt):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is not None and _is_empty_or_default(value):
                    targets.update(name for name in _assigned_names(node) if any(token in name.lower() for token in _STAGE_TOKENS))
    if not targets:
        return set()
    returned: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Return) and getattr(node, "lineno", 0) > getattr(handler, "lineno", 0) and node.value is not None:
            returned.update(child.id for child in ast.walk(node.value) if isinstance(child, ast.Name))
    return targets & returned


class HonestDegradationSkill:
    contract = SkillContract(
        "honest-degradation", "1.0",
        ("degraded input paths fail visibly or disclose their state",),
        ("silent exception fallback", "required deserialized field filled by a default"),
        ("AST evidence of a fallback body or deserialized payload access",),
        ("direct Python AST only; aliases, framework error handlers, and downstream flag consumers are not resolved",),
    )

    def applicability(self, context: EvaluationContext) -> Applicability:
        return live_python(context, "except" in context.source or ".get(" in context.source or "getattr(" in context.source)

    def evaluate(self, context: EvaluationContext):
        tree = parse(context.source)
        if tree is None:
            return ()
        findings = []
        parents = _parent_map(tree)
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            body = handler.body
            # Logging alone is not sufficient for handlers that drop an item
            # or stage result; the caller needs structural visibility too.
            has_raise = any(isinstance(node, ast.Raise) for stmt in body for node in ast.walk(stmt))
            has_flag = _has_visibility_action(body)
            drops_item = any(isinstance(node, ast.Continue) for stmt in body for node in ast.walk(stmt))
            silent_return = any(isinstance(node, (ast.Return, ast.Pass)) for stmt in body for node in ast.walk(stmt))
            function = _nearest_function(handler, parents)
            if _handles_specific_parse_or_decode_error(handler):
                continue
            loop_drop = (
                drops_item
                and _handler_is_in_loop(handler, parents)
                and _function_returns_collection_built_in_loop(function)
            )
            default_return = _default_return_values(body)
            required_stage_return = default_return and (
                _function_is_required_stage(function) or _try_body_touches_stage(handler, parents)
            )
            stage_swallow = _stage_swallow_targets(handler, function)
            if loop_drop and not (has_raise or has_flag):
                detail = "exception handler drops an item in a loop; output silently reduced without degraded state"
                findings.append(source_finding(context, self.contract.name, handler, detail, "A logged-and-continued degraded path can still produce a plausible partial result, so the caller cannot distinguish complete evaluation from discarded evidence."))
            elif stage_swallow and not (has_raise or has_flag):
                names_rendered = ", ".join(sorted(stage_swallow))
                detail = f"exception handler leaves stage result `{names_rendered}` discarded without marking degraded state"
                findings.append(source_finding(context, self.contract.name, handler, detail, "A stage result is replaced with an empty/default value that flows into the returned result, so a failed stage can be presented as ordinary partial output."))
            elif silent_return and required_stage_return and not (has_raise or has_flag):
                detail = "exception handler returns a plausible fallback without raising or marking degraded state"
                findings.append(source_finding(context, self.contract.name, handler, detail, "A degraded-input handler is structurally silent, so callers cannot distinguish fallback data from verified data."))

        deserialized: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and call_name(node.value) in {"json.loads", "pickle.loads", "yaml.load", "yaml.safe_load"}:
                deserialized.update(target.id for target in node.targets if isinstance(target, ast.Name))
        required_tokens = {"id", "version", "schema", "hash", "signature", "payload", "data"}
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            receiver = None
            key_node = default = None
            if isinstance(call.func, ast.Attribute) and call.func.attr == "get" and len(call.args) >= 2:
                receiver, key_node, default = call.func.value, call.args[0], call.args[1]
            elif isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 3:
                receiver, key_node, default = call.args[0], call.args[1], call.args[2]
            if not isinstance(receiver, ast.Name) or receiver.id not in deserialized or key_node is None or default is None:
                continue
            key = key_node.value.lower() if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str) else ""
            if key not in required_tokens or (isinstance(default, ast.Constant) and default.value is None):
                continue
            detail = f"deserialized required field `{key}` is silently supplied by a default"
            findings.append(source_finding(context, self.contract.name, call, detail, "The parser fallback does not expose that required artifact input was absent."))
        return tuple(findings)
