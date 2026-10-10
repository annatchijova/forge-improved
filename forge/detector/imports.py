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

Java
    An import names a fully-qualified type, and a public type conventionally
    lives in the file named after it inside its package directory. Siblings in
    the same package are referenced with no import at all, so those are counted
    by simple name -- bounded to the package, never repository-wide.
C#
    A ``using`` imports a *namespace* rather than a type, so it credits every
    file declaring it; types are then named simply, counted within the
    namespace.
Ruby
    ``require_relative`` and ``require`` resolve to files, but a Rails
    application autoloads by convention and often contains no ``require`` at
    all. A file is reached by something naming the constant it defines, so the
    constant is derived from the filename and counted -- and dropped entirely
    when two files would claim the same one.
PHP
    PSR-4 puts one class in one file named after it, so a declared
    ``namespace`` plus the filename resolves a ``use`` exactly. Literal
    ``require`` paths resolve relative to the including file.
C/C++
    Only a quoted ``#include`` can name a repository file; an angle-bracket
    include is a system header. A translation unit is compiled rather than
    included, so only headers can be shown orphaned.

Every language a pack can analyse now resolves its own references. The stem
tally survives only for recognised languages with no pack at all, and triage
records that their connectivity is approximate rather than pretending
otherwise.
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
def _scoped_name_references(
    texts: dict[str, str], names: dict[str, str],
) -> dict[str, set[str]]:
    """Credit each file that mentions another's declared name, in one pass.

    Used only *within* a package or namespace, never across the repository. A
    simple name is weak evidence globally -- two classes called ``Config`` in
    different packages are different classes -- but inside one package it is
    exactly how the language refers to a sibling, with no import statement to
    resolve. Scanning all names at once keeps this linear in total text rather
    than quadratic in members.
    """
    if len(names) < 2:
        return {}
    pattern = re.compile(r"\b(" + "|".join(re.escape(name) for name in sorted(names)) + r")\b")
    references: dict[str, set[str]] = {}
    for source, text in texts.items():
        for name in set(pattern.findall(text)):
            target = names[name]
            if target != source:
                references.setdefault(target, set()).add(source)
    return references


_JAVA_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;", re.M)


def java_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Resolve Java imports through declared packages, plus same-package use.

    A Java import names a fully-qualified type, and by convention a public type
    lives in the file named after it inside its package directory -- so the
    declared ``package`` plus the filename is enough to resolve one exactly.
    A wildcard import credits the whole package.

    Sibling types in the same package are referenced with no import at all, so
    those are counted by simple name, bounded to that package.
    """
    sources = [path for path in paths if path.suffix.lower() == ".java"]
    if not sources:
        return {}
    texts = {str(path.relative_to(root)): _read(path) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in texts}
    by_fqn: dict[str, str] = {}
    by_package: dict[str, dict[str, str]] = {}
    for relative, text in texts.items():
        match = _JAVA_PACKAGE.search(text)
        package = match.group(1) if match else ""
        simple = PurePosixPath(relative).stem
        by_fqn[f"{package}.{simple}" if package else simple] = relative
        by_package.setdefault(package, {})[simple] = relative
    for relative, text in texts.items():
        for imported in _JAVA_IMPORT.findall(text):
            if imported.endswith(".*"):
                for target in by_package.get(imported[:-2], {}).values():
                    if target != relative:
                        references[target].add(relative)
            elif imported in by_fqn and by_fqn[imported] != relative:
                references[by_fqn[imported]].add(relative)
    for package, members in by_package.items():
        scoped = {name: text for name, text in texts.items() if name in set(members.values())}
        for target, callers in _scoped_name_references(scoped, members).items():
            references[target].update(callers)
    return references


_CSHARP_NAMESPACE = re.compile(r"^\s*namespace\s+([\w.]+)", re.M)
_CSHARP_USING = re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?([\w.]+)\s*;", re.M)


def csharp_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Resolve C# ``using`` directives against declared namespaces.

    A ``using`` imports a *namespace*, not a type, so it credits every file
    declaring that namespace. Types are then referenced by simple name, which
    is counted inside the namespace only -- the same bound Java's same-package
    rule uses, and for the same reason.
    """
    sources = [path for path in paths if path.suffix.lower() == ".cs"]
    if not sources:
        return {}
    texts = {str(path.relative_to(root)): _read(path) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in texts}
    by_namespace: dict[str, dict[str, str]] = {}
    for relative, text in texts.items():
        match = _CSHARP_NAMESPACE.search(text)
        namespace = match.group(1) if match else ""
        by_namespace.setdefault(namespace, {})[PurePosixPath(relative).stem] = relative
    for relative, text in texts.items():
        for used in _CSHARP_USING.findall(text):
            for target in by_namespace.get(used, {}).values():
                if target != relative:
                    references[target].add(relative)
    for namespace, members in by_namespace.items():
        scoped = {name: text for name, text in texts.items() if name in set(members.values())}
        for target, callers in _scoped_name_references(scoped, members).items():
            references[target].update(callers)
    return references


_RUBY_REQUIRE = re.compile(r"\brequire(?P<relative>_relative)?\s*\(?\s*['\"]([^'\"\n]+)['\"]")


def _camelize(stem: str) -> str:
    """Convert a Ruby filename stem to the constant it conventionally defines."""
    return "".join(part[:1].upper() + part[1:] for part in stem.split("_") if part)


def ruby_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Resolve Ruby requires, and the constant references autoloading relies on.

    ``require_relative`` resolves against the requiring file's directory and
    ``require`` against the repository's load-path-ish roots. Neither is enough
    on its own: a Rails application autoloads by *convention* and frequently
    contains no ``require`` at all, so a file is reached purely by something
    naming the constant it defines. Deriving that constant from the filename
    and counting whole-word references to it is how the graph gets built at all
    for such a project -- and a camelized constant is distinctive enough that
    this is far tighter than the repository-wide stem tally it replaces.
    """
    sources = [path for path in paths if path.suffix.lower() in {".rb", ".rake"}]
    if not sources:
        return {}
    texts = {str(path.relative_to(root)): _read(path) for path in sources}
    known = set(texts)
    references: dict[str, set[str]] = {name: set() for name in known}
    for relative, text in texts.items():
        for is_relative, specifier in _RUBY_REQUIRE.findall(text):
            target = _resolve_ruby_require(relative, specifier, known, bool(is_relative))
            if target and target != relative:
                references[target].add(relative)
    constants: dict[str, str] = {}
    for relative in known:
        constant = _camelize(PurePosixPath(relative).stem)
        # An ambiguous constant proves nothing: two files claiming `Config`
        # would each inherit the other's callers, which is the exact defect the
        # stem tally had.
        constants[constant] = "" if constant in constants else relative
    unambiguous = {name: target for name, target in constants.items() if target}
    for target, callers in _scoped_name_references(texts, unambiguous).items():
        references[target].update(callers)
    return references


def _resolve_ruby_require(
    source: str, specifier: str, known: set[str], relative: bool,
) -> str | None:
    candidate = specifier if specifier.endswith(".rb") else specifier + ".rb"
    if relative:
        return _first_known([_normalize(str(PurePosixPath(source).parent / candidate))], known)
    direct = [candidate, f"lib/{candidate}", f"app/{candidate}"]
    resolved = _first_known([_normalize(item) for item in direct], known)
    if resolved:
        return resolved
    # A bare `require "foo/bar"` may resolve through a configured load path the
    # scanner cannot see. Accept a unique trailing match and nothing else.
    matches = [item for item in known if item.endswith("/" + candidate)]
    return matches[0] if len(matches) == 1 else None


def _first_known(candidates: list[str], known: set[str]) -> str | None:
    return next((item for item in candidates if item in known), None)


_PHP_NAMESPACE = re.compile(r"^\s*namespace\s+([\w\\]+)\s*[;{]", re.M)
_PHP_USE = re.compile(r"^\s*use\s+(?:function\s+|const\s+)?([\w\\]+)", re.M)
_PHP_INCLUDE = re.compile(
    r"\b(?:include|include_once|require|require_once)\s*\(?\s*"
    r"(?:__DIR__\s*\.\s*)?['\"]([^'\"\n]+)['\"]"
)


def php_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Resolve PHP ``use`` against declared namespaces, plus literal includes.

    PSR-4 puts one class in one file named after it, so a declared
    ``namespace`` plus the filename resolves a ``use`` exactly. A literal
    ``require`` path is resolved relative to the including file, which is how
    projects without an autoloader are wired.
    """
    sources = [path for path in paths if path.suffix.lower() in {".php", ".phtml"}]
    if not sources:
        return {}
    texts = {str(path.relative_to(root)): _read(path) for path in sources}
    known = set(texts)
    references: dict[str, set[str]] = {name: set() for name in known}
    by_fqn: dict[str, str] = {}
    for relative, text in texts.items():
        match = _PHP_NAMESPACE.search(text)
        namespace = match.group(1).strip("\\") if match else ""
        simple = PurePosixPath(relative).stem
        by_fqn[f"{namespace}\\{simple}" if namespace else simple] = relative
    for relative, text in texts.items():
        for used in _PHP_USE.findall(text):
            target = by_fqn.get(used.strip("\\"))
            if target and target != relative:
                references[target].add(relative)
        for included in _PHP_INCLUDE.findall(text):
            target = _normalize(str(PurePosixPath(relative).parent / included.lstrip("/")))
            if target in known and target != relative:
                references[target].add(relative)
    return references


C_SUFFIXES = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"})
_C_INCLUDE_LOCAL = re.compile(r'^\s*#\s*include\s*"([^"\n]+)"', re.M)
#: Common places a build system puts headers on the include path.
_C_INCLUDE_ROOTS = ("", "include/", "src/", "lib/", "inc/")


def c_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Resolve ``#include "..."`` to repository headers.

    Only the quoted form can name a repository file; ``#include <stdio.h>`` is a
    system header and credits nothing, the same way a bare npm specifier does.
    A quoted include resolves against the including file's directory first and
    then the conventional header roots, and an ambiguous trailing match is left
    unresolved rather than guessed.

    Note what this graph does *not* contain. A translation unit is compiled by
    the build system, never included, so ``.c`` and ``.cpp`` files have no
    callers here by construction -- the pack marks them entry points for that
    reason. Only headers can be shown orphaned.
    """
    sources = [path for path in paths if path.suffix.lower() in C_SUFFIXES]
    if not sources:
        return {}
    known = {str(path.relative_to(root)) for path in sources}
    references: dict[str, set[str]] = {name: set() for name in known}
    for path in sources:
        source = str(path.relative_to(root))
        for included in _C_INCLUDE_LOCAL.findall(_read(path)):
            target = _resolve_c_include(source, included, known)
            if target and target != source:
                references[target].add(source)
    return references


def _resolve_c_include(source: str, included: str, known: set[str]) -> str | None:
    relative = _normalize(str(PurePosixPath(source).parent / included))
    candidates = [relative] + [_normalize(prefix + included) for prefix in _C_INCLUDE_ROOTS]
    resolved = _first_known(candidates, known)
    if resolved:
        return resolved
    # The real include path is a build-system fact this scanner cannot see.
    # Accept a unique trailing match and nothing else, because crediting the
    # wrong header is worse than leaving connectivity undetermined.
    matches = [item for item in known if item.endswith("/" + included)]
    return matches[0] if len(matches) == 1 else None


RESOLVED_SUFFIXES = frozenset({
    ".go", ".rs", ".java", ".cs", ".rb", ".rake", ".php", ".phtml",
}) | JS_SUFFIXES | C_SUFFIXES

_RESOLVERS = (
    javascript_references, go_references, rust_references,
    java_references, csharp_references, ruby_references, php_references,
    c_references,
)


def resolved_references(root: Path, paths: Iterable[Path]) -> dict[str, set[str]]:
    """Merge every language resolver into one reference map."""
    paths = list(paths)
    merged: dict[str, set[str]] = {}
    for resolver in _RESOLVERS:
        for target, callers in resolver(root, paths).items():
            merged.setdefault(target, set()).update(callers)
    return merged


__all__ = (
    "C_SUFFIXES", "JS_EXTENSIONS", "JS_SUFFIXES", "RESOLVED_SUFFIXES",
    "c_references", "csharp_references",
    "go_references", "java_references", "javascript_references",
    "php_references", "resolved_references", "ruby_references",
    "rust_references",
)
