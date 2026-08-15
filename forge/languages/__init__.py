"""Registry of the source languages FORGE can analyse, and at what depth.

FORGE analyses source at two depths and must never let a reader confuse them:

``ast``
    A real parse tree. Python only. Findings can be verified structurally and,
    where a harness exists, reproduced by induction.
``lexical``
    A masked-text scan driven by a :class:`~forge.languages.spec.LanguagePack`.
    Comments and string data are blanked before any pattern runs, so a match is
    always real code -- but there is no scope, no type information and no
    reachability. Findings are observations a reviewer must confirm.

Anything not listed here is analysed at no depth at all, and coverage reports
it as an explicit abstention rather than as a clean result.

Adding a language means writing a pack and registering it below. It does not
mean writing an agent, which is the whole point of this module existing.
"""
from __future__ import annotations

from pathlib import Path

from forge.languages import go, javascript, rust
from forge.languages.engine import build_context, mask_source, read_source, scan_source
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


#: Packs in a fixed order. Iteration order reaches finding order, which reaches
#: the audit seal, so this is a tuple and never a set.
PACKS: tuple[LanguagePack, ...] = (javascript.PACK, go.PACK, rust.PACK)

#: Languages the web-facing agent owns, kept separate from the systems
#: languages so each agent declares an honest scope in its protocol.
WEB_PACKS: tuple[LanguagePack, ...] = (javascript.PACK,)
SYSTEMS_PACKS: tuple[LanguagePack, ...] = (go.PACK, rust.PACK)

#: Extensions parsed into a real AST. Kept here so coverage has one source of
#: truth for analysis depth instead of rediscovering ``.py`` in five modules.
AST_EXTENSIONS: frozenset[str] = frozenset({".py"})

AST_LANGUAGE_NAMES: dict[str, str] = {".py": "Python"}


def _extension_index(packs: tuple[LanguagePack, ...]) -> dict[str, LanguagePack]:
    index: dict[str, LanguagePack] = {}
    for pack in packs:
        for extension in pack.extensions:
            if extension in index:
                raise ValueError(
                    f"extension {extension} is claimed by both "
                    f"{index[extension].name} and {pack.name}"
                )
            index[extension] = pack
    return index


_BY_EXTENSION = _extension_index(PACKS)

#: Every extension any pack can scan lexically.
LEXICAL_EXTENSIONS: frozenset[str] = frozenset(_BY_EXTENSION)

#: Extensions FORGE analyses at any depth. This is the denominator that
#: ``eligible_source_files`` uses: a language with no detector must not be
#: counted as source FORGE was expected to cover.
ANALYZED_EXTENSIONS: frozenset[str] = AST_EXTENSIONS | LEXICAL_EXTENSIONS


#: Every extension FORGE recognizes as a programming language, including the
#: ones it has no detector for. Coverage needs this to tell "a source file in a
#: language nothing reached" (a reportable engine limit a reviewer may want
#: closed) apart from "a README" (nothing to report at all). Previously both
#: landed in one bucket, which made prose look like an audit gap.
RECOGNIZED_LANGUAGES: dict[str, str] = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript/TypeScript", ".jsx": "JavaScript/TypeScript",
    ".mjs": "JavaScript/TypeScript", ".cjs": "JavaScript/TypeScript",
    ".ts": "JavaScript/TypeScript", ".tsx": "JavaScript/TypeScript",
    ".mts": "JavaScript/TypeScript", ".cts": "JavaScript/TypeScript",
    ".go": "Go", ".rs": "Rust",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala", ".rb": "Ruby",
    ".php": "PHP", ".cs": "C#", ".swift": "Swift", ".m": "Objective-C",
    ".c": "C", ".h": "C/C++", ".hpp": "C++", ".cc": "C++", ".cpp": "C++",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".lua": "Lua",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".dart": "Dart",
}


def pack_for_suffix(suffix: str) -> LanguagePack | None:
    """Return the pack owning a file extension, or ``None`` when unsupported."""
    return _BY_EXTENSION.get(suffix.lower())


def pack_for_path(path: str | Path) -> LanguagePack | None:
    return pack_for_suffix(Path(path).suffix)


def language_name(suffix: str) -> str | None:
    """Return the display language for an extension FORGE can analyse."""
    normalized = suffix.lower()
    if normalized in AST_LANGUAGE_NAMES:
        return AST_LANGUAGE_NAMES[normalized]
    pack = _BY_EXTENSION.get(normalized)
    return pack.name if pack else None


def analysis_depth(suffix: str) -> str:
    """Return ``"ast"``, ``"lexical"`` or ``"none"`` for one extension.

    Coverage and the report use this to say *how* a file was analysed. A
    lexical result presented beside an AST result without that distinction
    would overstate what the run established.
    """
    normalized = suffix.lower()
    if normalized in AST_EXTENSIONS:
        return "ast"
    return "lexical" if normalized in _BY_EXTENSION else "none"


def entry_point_names() -> frozenset[str]:
    """Filenames that are executable entry points by convention in any pack."""
    return frozenset(name for pack in PACKS for name in pack.entry_point_names)


def scan_path(path: str | Path, root: str | Path) -> tuple[tuple[LexicalFinding, ...], str]:
    """Scan one file with its owning pack.

    Returns the findings and an examination reason, so a caller can record why
    a file produced nothing: excluded by scope, unreadable, or genuinely clean.
    """
    file_path, base = Path(path), Path(root)
    relative = str(file_path.relative_to(base))
    pack = pack_for_path(file_path)
    if pack is None:
        return (), "excluded_by_scope"
    source, reason = read_source(file_path)
    if source is None:
        return (), reason or "unreadable_file"
    findings = scan_source(pack, relative, source)
    return tuple(findings), "examined_with_findings" if findings else "examined_clean"


__all__ = (
    "ANALYZED_EXTENSIONS", "AST_EXTENSIONS", "LEXICAL_EXTENSIONS", "PACKS",
    "RECOGNIZED_LANGUAGES", "SYSTEMS_PACKS", "WEB_PACKS", "LanguagePack",
    "LexicalFinding", "ScanContext", "SinkRule", "StringRule", "analysis_depth",
    "build_context", "entry_point_names", "language_name", "mask_source",
    "pack_for_path", "pack_for_suffix", "scan_path", "scan_source",
)
