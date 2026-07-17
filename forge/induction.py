"""Conservative, time-bounded execution for parser and eval/exec hypotheses.

Induction is deliberately narrower than arbitrary fuzzing.  It only invokes a
module-level function in a spawned child process. Parser hypotheses receive
synthetic malformed text; eval/exec hypotheses receive a sentinel payload
that may write only inside the child sandbox. Other hypothesis families remain
AST-only until a family-specific harness exists.
"""
from __future__ import annotations

import ast
import builtins
import io
import importlib.util
import inspect
import multiprocessing
import os
import resource
import socket
import subprocess
import sys
import tempfile
import traceback
from queue import Empty
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


_NAMED_BOUNDARY_ERRORS = {"JSONDecodeError", "ValueError", "YAMLError", "TomlDecodeError", "ForgeArtifactError"}
INDUCTION_TIMEOUT_SECONDS = 1.0
INDUCTION_MEMORY_BYTES = 512 * 1024 * 1024
INDUCTION_FILE_DESCRIPTORS = 64


@dataclass(frozen=True)
class InductionResult:
    status: str
    family: str
    detail: str
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _function_for_line(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    candidates = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not (node.lineno <= line <= getattr(node, "end_lineno", node.lineno)):
            continue
        parent = parents.get(node)
        nested = False
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested = True
                break
            parent = parents.get(parent)
        if not nested:
            candidates.append(node)
    return min(candidates, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno, default=None)


_MALFORMED_TEXT = "{not valid json"


def _synthetic_value(name: str, annotation: Any) -> Any:
    """Synthesize a malformed argument shaped like the parameter's own type.

    A parser hypothesis claims a specific content-parsing failure (bad JSON,
    bad YAML, a syntax error) escapes uncaught. Passing the same raw string
    regardless of the parameter's annotation used to conflate two different
    things: a `path: Path` parameter fed a plain `str` raises AttributeError
    from a type mismatch (`'str' object has no attribute 'read_text'`) before
    the function's own parsing/exception-handling code ever runs - that is
    not evidence the hypothesized parsing failure is unhandled, it is an
    artifact of the harness attacking the wrong argument type entirely. A
    Path-annotated parameter gets a real Path to a real file containing the
    malformed text instead, so the function's own read + parse + exception
    handling actually executes and induction tests what the hypothesis
    claims, not a TypeError the harness invented.
    """
    if "Path" in str(annotation):
        target = Path(f"forge-induction-argument-{name}.txt")
        target.write_text(_MALFORMED_TEXT, encoding="utf-8")
        return target
    return _MALFORMED_TEXT


def _module_name(root: Path, module_path: str) -> str | None:
    """Return a package-qualified module name when the path has a package."""
    path = Path(module_path)
    parts = list(path.with_suffix("").parts)
    if not parts or any(part == ".." for part in parts):
        return None
    package_parts: list[str] = []
    for part in parts[:-1]:
        package_parts.append(part)
        if not (root.joinpath(*package_parts) / "__init__.py").is_file():
            return None
    return ".".join(parts)


def _apply_worker_limits() -> None:
    """Apply best-effort child limits; unsupported limits remain explicit."""
    limits = (
        (resource.RLIMIT_CPU, (1, 1)),
        (resource.RLIMIT_AS, (INDUCTION_MEMORY_BYTES, INDUCTION_MEMORY_BYTES)),
        (resource.RLIMIT_NOFILE, (INDUCTION_FILE_DESCRIPTORS, INDUCTION_FILE_DESCRIPTORS)),
    )
    for limit, values in limits:
        try:
            resource.setrlimit(limit, values)
        except (OSError, ValueError, AttributeError):
            continue


def _apply_worker_sandbox(sandbox: Path) -> None:
    """Deny process, network and out-of-sandbox writes in an induction child.

    RLIMITs constrain resource use but do not stop a target module's import
    side effects. This guard is installed before importing target code. It is
    intentionally deny-by-default for execution/network and permits writes
    only to the child-owned temporary directory used for synthetic fixtures.
    It is defense in depth, not a claim of a kernel security boundary.
    """
    root = sandbox.resolve()
    original_open, original_io_open, original_os_open = builtins.open, io.open, os.open

    def writable_path(value: Any) -> bool:
        if isinstance(value, int):
            return True
        try:
            candidate = Path(value).resolve()
        except (OSError, TypeError, ValueError):
            return False
        return candidate == root or root in candidate.parents

    def denied(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("FORGE induction sandbox blocks process, network, and destructive operations")

    def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any):
        if any(flag in mode for flag in ("w", "a", "x", "+")) and not writable_path(file):
            raise PermissionError("FORGE induction sandbox blocks writes outside its temporary directory")
        return original_open(file, mode, *args, **kwargs)

    def guarded_io_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any):
        if any(flag in mode for flag in ("w", "a", "x", "+")) and not writable_path(file):
            raise PermissionError("FORGE induction sandbox blocks writes outside its temporary directory")
        return original_io_open(file, mode, *args, **kwargs)

    def guarded_os_open(file: Any, flags: int, *args: Any, **kwargs: Any):
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if flags & write_flags and not writable_path(file):
            raise PermissionError("FORGE induction sandbox blocks writes outside its temporary directory")
        return original_os_open(file, flags, *args, **kwargs)

    builtins.open = guarded_open
    io.open = guarded_io_open
    os.open = guarded_os_open
    for name in ("system", "popen", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnve"):
        if hasattr(os, name):
            setattr(os, name, denied)
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        setattr(subprocess, name, denied)
    for name in ("remove", "unlink", "rmdir", "removedirs"):
        if not hasattr(os, name):
            continue
        original = getattr(os, name)
        def guarded_remove(path: Any, *args: Any, _original=original, **kwargs: Any):
            if not writable_path(path):
                return denied()
            return _original(path, *args, **kwargs)
        setattr(os, name, guarded_remove)
    for name in ("rename", "replace"):
        if not hasattr(os, name):
            continue
        original = getattr(os, name)
        def guarded_rename(source: Any, destination: Any, *args: Any, _original=original, **kwargs: Any):
            if not writable_path(source) or not writable_path(destination):
                return denied()
            return _original(source, destination, *args, **kwargs)
        setattr(os, name, guarded_rename)
    socket.socket = denied


_EVAL_SENTINEL_NAME = "forge-eval-induction-sentinel.txt"
_EVAL_SENTINEL_PAYLOAD = f"open({_EVAL_SENTINEL_NAME!r}, 'w').write('confirmed')"


def _invoke_worker(root: str, module_path: str, function_name: str, target_line: int, family: str, queue: Any) -> None:
    try:
        root_path = Path(root)
        with tempfile.TemporaryDirectory(prefix="forge-induction-") as sandbox:
            os.chdir(sandbox)
            _apply_worker_limits()
            _apply_worker_sandbox(Path(sandbox))
            qualified_name = _module_name(root_path, module_path)
            if qualified_name:
                sys.path.insert(0, str(root_path))
                try:
                    module = importlib.import_module(qualified_name)
                except BaseException as exc:
                    queue.put(("import-error", type(exc).__name__, str(exc)[:240]))
                    return
            else:
                module_name = f"forge_induction_{abs(hash(module_path))}"
                spec = importlib.util.spec_from_file_location(module_name, root_path / module_path)
                if spec is None or spec.loader is None:
                    queue.put(("import-error", "ModuleSpecError", "module spec unavailable"))
                    return
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                except BaseException as exc:
                    queue.put(("import-error", type(exc).__name__, str(exc)[:240]))
                    return
            function = getattr(module, function_name)
            signature = inspect.signature(function)
            args: list[Any] = []
            for parameter in signature.parameters.values():
                if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
                    continue
                if parameter.kind is parameter.KEYWORD_ONLY and parameter.default is not parameter.empty:
                    continue
                if parameter.default is not parameter.empty and parameter.kind is not parameter.KEYWORD_ONLY:
                    continue
                value = _synthetic_value(parameter.name, parameter.annotation)
                if family == "eval/exec" and isinstance(value, str):
                    value = _EVAL_SENTINEL_PAYLOAD
                args.append(value)
            result = function(*args)
            if family == "eval/exec":
                queue.put(("eval-sentinel", (Path(_EVAL_SENTINEL_NAME)).is_file()))
                return
            queue.put(("returned", type(result).__name__))
    except BaseException as exc:  # child boundary: never leak target exceptions to the audit process
        target_file = str((Path(root) / module_path).resolve())
        frames = traceback.extract_tb(exc.__traceback__)
        target_frames = [frame for frame in frames if str(Path(frame.filename).resolve()) == target_file]
        at_hypothesized_call = any(frame.lineno == target_line for frame in target_frames)
        frame_detail = ", ".join(f"{frame.filename}:{frame.lineno}" for frame in target_frames[-3:])
        queue.put(("exception", type(exc).__name__, str(exc)[:240], at_hypothesized_call, frame_detail))


def induce_hypothesis(root: str | Path, module_path: str, line: int, description: str) -> InductionResult:
    if "parser call" in description.lower():
        family = "parser"
    elif "dynamic evaluation" in description.lower():
        family = "eval/exec"
    else:
        family = "unsupported"
    if family not in {"parser", "eval/exec"}:
        return InductionResult("UNDETERMINED", family, "No executable harness is registered for this hypothesis family.", "AST-only verification")
    path = (Path(root) / module_path).resolve()
    root_path = Path(root).resolve()
    if path.suffix != ".py" or root_path not in path.parents:
        return InductionResult("UNDETERMINED", family, "Module is outside the permitted Python audit scope.", str(path))
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
        function = _function_for_line(tree, line)
    except (OSError, SyntaxError) as exc:
        return InductionResult("UNDETERMINED", family, f"Cannot prepare isolated execution: {exc}", f"{module_path}:{line}")
    if function is None or isinstance(function, ast.AsyncFunctionDef):
        return InductionResult("UNDETERMINED", family, "No synchronous module-level function boundary was found.", f"{module_path}:{line}")

    # Test the public detector boundary when the parser call is in a private
    # helper. This avoids treating trusted lexicon loaders as user-input APIs.
    function_name = function.name
    if function_name.startswith("_"):
        public_entrypoint = next(
            (node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name == "analyze"),
            None,
        )
        if public_entrypoint is not None:
            function_name = public_entrypoint.name

    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(target=_invoke_worker, args=(str(root_path), module_path, function_name, line, family, queue))
    process.start()
    process.join(INDUCTION_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(0.5)
        return InductionResult("UNDETERMINED", family, f"Induction timed out after {INDUCTION_TIMEOUT_SECONDS}s; child process was terminated.", f"{module_path}:{line}")
    try:
        result = queue.get(timeout=0.2)
    except Empty:
        return InductionResult("UNDETERMINED", family, f"Child exited without a result (exitcode={process.exitcode}).", f"{module_path}:{line}")
    if result[0] == "import-error":
        return InductionResult("UNDETERMINED", family, f"Target module could not be loaded in its package context: {result[1]}: {result[2]}", f"{module_path}:{line}")
    if result[0] == "eval-sentinel":
        if result[1]:
            return InductionResult("CONFIRMED BY INDUCTION", family, "Isolated eval/exec payload created the in-sandbox sentinel.", f"{module_path}:{line}: {_EVAL_SENTINEL_NAME}")
        return InductionResult("FALSIFIED", family, "Isolated eval/exec payload returned without creating the in-sandbox sentinel.", f"{module_path}:{line}: sentinel absent")
    if result[0] == "exception":
        error_name, detail = result[1], result[2]
        at_hypothesized_call = bool(result[3]) if len(result) > 3 else False
        frame_detail = result[4] if len(result) > 4 else ""
        evidence = f"{module_path}:{line}: {error_name}: {detail}"
        if frame_detail:
            evidence += f" [target frames: {frame_detail}]"
        if error_name == "PermissionError" and "FORGE induction sandbox" in detail:
            return InductionResult("UNDETERMINED", family, "Induction was blocked by the sandbox policy rather than the target's own boundary.", evidence)
        if not at_hypothesized_call:
            return InductionResult("ERROR_PATH_REACHABLE", family, f"Malformed input reached an opaque {error_name}, but the exception did not originate at the hypothesized parser call.", evidence)
        if error_name in _NAMED_BOUNDARY_ERRORS:
            return InductionResult("FALSIFIED", family, f"Named boundary error {error_name} was raised for malformed input.", evidence)
        return InductionResult("CONFIRMED BY INDUCTION", family, f"Malformed input raised opaque {error_name} at the hypothesized parser call.", evidence)
    if result[0] == "returned":
        return InductionResult("FALSIFIED", family, "Malformed input was accepted without an exception.", f"{module_path}:{line}: returned {result[1]}")
    return InductionResult("UNDETERMINED", family, str(result[1]), f"{module_path}:{line}")
