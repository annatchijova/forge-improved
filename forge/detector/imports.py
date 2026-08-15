"""Per-language import resolution for the module connectivity graph.

Triage decides whether a module is CONNECTED_ALIVE or DEAD_WEIGHT from how
many other modules reference it. Python has always had a real answer to that
question, because ``ast`` resolves an import to a file. Every other language
shared one fallback: count how many times a file's *stem* appeared on any
import-looking line anywhere in the repository.

That fallback is wrong in both directions, and the errors are not symmetric
noise. Two files named ``config.ts`` in different directories were
indistinguishable, so a genuinely orphaned one inherited the other's callers
and was classified as alive. An import of the npm package ``store`` credited a
local ``store.go`` that nothing referenced. And a Rust file reachable only
through a ``mod`` declaration -- the actual mechanism by which Rust wires a
crate together -- scored zero and was reported as dead weight.

Each resolver here answers the question the language actually asks:

Go
    Imports name a *package directory*, not a file, so an import credits every
    file in the resolved directory. The module path comes from ``go.mod`` when
    present; without it, a trailing-path match is used and stays conservative.
Rust
    A file is part of a crate only if a ``mod`` declaration reaches it. That
    declaration chain, not ``use``, is the connectivity graph.
JavaScript/TypeScript
    Only relative specifiers can refer to a repository file. Bare specifiers
    are packages and are ignored, which is exactly the false credit the stem
    tally used to hand out.

Languages with no resolver here keep the stem tally, and triage records that
their connectivity is approximate rather than pretending otherwise.
"""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Iterable


JS_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
JS_SUFFIXES = frozenset(JS_EXTENSIONS)

#: ``import x from "y"``, ``import "y"``, ``require("y")``, ``import("y")`` and
#: ``export * from "y"`` all reduce to one quoted specifier in a known context.
_JS_SPECIFIER = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"]([^'"\n]+)['"]"""
)
_GO_IMPORT_BLOCK = re.compile(r"\bimport\s*\(([^)]*)\)", re.S)
_GO_IMPORT_SINGLE = re.compile(r"\bimport\s+(?:[\w.]+\s+)?\"([^\"\n]+)\"")
_GO_QUOTED = re.compile(r"\"([^\"\n]+)\"")
_GO_MODULE = re.compile(r"^\s*module\s+(\S+)", re.M)
_RUST_MOD = re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;", re.M)
_RUST_USE_CRATE = re.compile(r"\buse\s+crate::((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _normalize(candidate: str) -> str:
    return str(PurePosixPath(os.path.normpath(candidate)))


def _resolve_javascript(source: str, specifier: str, known: set[str]) -> str | None:
    """Resolve a relative specifier to a repository file, or ``None``.

    Bare specifiers (``react``, ``lodash/get``) name packages and are dropped:
    crediting a local file because a dependency shares its name is the precise
    false positive this resolver exists to remove.
    """
    if not specifier.startswith("."):
        return None
    target = _normalize(str(PurePosixPath(source).parent / specifier))
    candidates = [target]
    # TypeScript sources import ``./x.js`` to mean ``./x.ts``; try the written
    # extension first, then the source extension it compiles from.
    for extension in (".js", ".mjs", ".cjs"):
        if target.endswith(extension):
            stem = target[: -len(extension)]
            candidates.extend(stem + item for item in JS_EXTENSIONS)
    candidates.extend(target + item for item in JS_EXTENSIONS)
    candidates.extend(f"{target}/index{item}" for item in JS_EXTENSIONS)
    return next((item for item in candidates if item in known), None)


def javascript_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    sources = [path for path in paths if path.suffix.lower() in JS_SUFFIXES]
    known = {str(path.relative_to(root)) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in known}
    for path in sources:
        source = str(path.relative_to(root))
        for match in _JS_SPECIFIER.finditer(_read(path)):
            target = _resolve_javascript(source, match.group(1), known)
            if target and target != source:
                references[target].add(source)
    return references


def _go_module_path(root: Path) -> str | None:
    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return None
    match = _GO_MODULE.search(_read(go_mod))
    return match.group(1).strip() if match else None


def go_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    sources = [path for path in paths if path.suffix.lower() == ".go"]
    known = {str(path.relative_to(root)) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in known}
    by_directory: dict[str, list[str]] = {}
    for name in known:
        by_directory.setdefault(str(PurePosixPath(name).parent), []).append(name)
    module_path = _go_module_path(root)
    for path in sources:
        source = str(path.relative_to(root))
        text = _read(path)
        specifiers = set(_GO_IMPORT_SINGLE.findall(text))
        for block in _GO_IMPORT_BLOCK.findall(text):
            specifiers.update(_GO_QUOTED.findall(block))
        for specifier in specifiers:
            directory = _go_import_directory(specifier, module_path, by_directory)
            if directory is None:
                continue
            for target in by_directory[directory]:
                if target != source:
                    references[target].add(source)
    return references


def _go_import_directory(
    specifier: str, module_path: str | None, by_directory: dict[str, list[str]],
) -> str | None:
    """Map a Go import path to a repository package directory.

    With ``go.mod`` present the mapping is exact. Without it the import path
    cannot be anchored, so a trailing-segment match is used -- and only when it
    is unambiguous, because crediting the wrong package is worse than leaving
    connectivity undetermined.
    """
    if module_path and (specifier == module_path or specifier.startswith(module_path + "/")):
        relative = specifier[len(module_path):].strip("/")
        directory = relative or "."
        return directory if directory in by_directory else None
    if module_path:
        return None
    matches = [
        directory for directory in by_directory
        if directory != "." and specifier.endswith("/" + directory)
    ]
    return matches[0] if len(matches) == 1 else None


def _rust_child_directory(source: str) -> PurePosixPath:
    """Return the directory a file's ``mod`` declarations resolve against.

    A crate root or ``mod.rs`` owns its own directory; any other module file
    owns the subdirectory named after it.
    """
    path = PurePosixPath(source)
    if path.name in {"lib.rs", "main.rs", "mod.rs"}:
        return path.parent
    return path.parent / path.stem


def rust_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    sources = [path for path in paths if path.suffix.lower() == ".rs"]
    known = {str(path.relative_to(root)) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in known}
    crate_roots = sorted(
        {str(PurePosixPath(name).parent) for name in known
         if PurePosixPath(name).name in {"lib.rs", "main.rs"}}
    )
    for path in sources:
        source = str(path.relative_to(root))
        text = _read(path)
        directory = _rust_child_directory(source)
        for name in _RUST_MOD.findall(text):
            for candidate in (f"{directory}/{name}.rs", f"{directory}/{name}/mod.rs"):
                target = _normalize(candidate)
                if target in known and target != source:
                    references[target].add(source)
        for chain in _RUST_USE_CRATE.findall(text):
            segments = chain.split("::")
            for crate_root in crate_roots:
                for length in range(len(segments), 0, -1):
                    prefix = "/".join(segments[:length])
                    for candidate in (f"{crate_root}/{prefix}.rs", f"{crate_root}/{prefix}/mod.rs"):
                        target = _normalize(candidate)
                        if target in known and target != source:
                            references[target].add(source)
    return references


#: Extensions whose connectivity is resolved rather than approximated.
RESOLVED_SUFFIXES = frozenset({".go", ".rs"}) | JS_SUFFIXES

_RESOLVERS = (javascript_references, go_references, rust_references)


def resolved_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Merge every language resolver into one reference map."""
    paths = list(paths)
    merged: dict[str, set[str]] = {}
    for resolver in _RESOLVERS:
        for target, callers in resolver(root, paths).items():
            merged.setdefault(target, set()).update(callers)
    return merged


__all__ = (
    "JS_EXTENSIONS", "JS_SUFFIXES", "RESOLVED_SUFFIXES", "go_references",
    "javascript_references", "resolved_references", "rust_references",
)
