"""Rust language pack.

Rust's lexical surface needs more care than Go's. Lifetimes (``&'a str``) and
char literals share the apostrophe, raw strings carry a variable hash fence
(``r##"..."##``), block comments nest, and ordinary string literals may span
lines. Each of those is declared below so the masker never opens a phantom
literal and blanks the rest of a file.

The families reported here are the ones a lexical view can honestly support.
``unsafe-block`` is included not because an ``unsafe`` block is a defect -- it
usually is not -- but because it is the exact point where the compiler stops
providing the guarantee the rest of the language rests on, and an audit that
silently passed over it would be overstating its coverage.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


_TAINT_NAMES = re.compile(
    r"\b(?:user|request|req|input|param|query|arg|name|filename|target|upload)\w*\b", re.I
)
_PATH_SINKS = re.compile(
    r"\b(?:File::(?:open|create)"
    r"|fs::(?:read|read_to_string|read_dir|write|remove_file|remove_dir_all|copy|rename))\s*\("
)
_PATH_NORMALIZERS = re.compile(r"\.(?:canonicalize|file_name)\s*\(")
_PARSE_CALLS = re.compile(
    r"\b(?:serde_json|serde_yaml|toml|bincode)::from_(?:str|slice|reader)\s*\(|\.parse\s*(?:::<[^>]*>)?\s*\("
)
_PANICKING = re.compile(r"\.(?:unwrap|expect)\s*\(")
# Against masked source, so the quotes survive while their contents do not.
_LITERAL_BINDING = re.compile(r"\b(?:let|const|static)\s+(?:mut\s+)?(\w+)[^=\n]*=\s*\"[^\"\n]*\"\s*;")
_LITERAL_RECEIVER = re.compile(r"\"[^\"\n]*\"\s*$")
_RECEIVER_NAME = re.compile(r"(\w+)\s*$")
_UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
_SQL_EXEC = re.compile(r"\b(?:sqlx::query|query|query_as|execute|batch_execute)\s*\(")
_SQL_CONSTRUCTED = re.compile(r"format!\s*\(|\"\s*\+|\+\s*\"|\.push_str\s*\(")
_COMMAND_NEW = re.compile(r"\bCommand::new\s*\(")
_SHELLS = ("sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    """Credential-named bindings holding a non-placeholder string literal."""
    return credential_findings(context, "Rust")


def _shell_commands(context: ScanContext) -> list[LexicalFinding]:
    """``Command::new`` starting a shell that will re-parse a built argument."""
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _COMMAND_NEW.search(masked)
        if not match:
            continue
        literals = re.findall(r"\"((?:[^\"\\]|\\.)*)\"", context.raw_line(number))
        if not literals or literals[0].strip().lower() not in _SHELLS:
            continue
        span = call_span(context, number)
        if not _SQL_CONSTRUCTED.search(span if span is not None else masked):
            continue
        findings.append(LexicalFinding(
            "command-injection", context.path, number,
            f"constructed argument reaches a {literals[0]} shell invocation",
            column=match.start() + 1, language="Rust",
        ))
    return findings


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Filesystem calls whose path shows no visible canonicalization."""
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _PATH_SINKS.search(masked)
        if not match:
            continue
        span = call_span(context, number)
        text = span if span is not None else masked
        names = set(_TAINT_NAMES.findall(text))
        if not names - set(context.sanitized_names) or _PATH_NORMALIZERS.search(text):
            continue
        findings.append(LexicalFinding(
            "path-traversal", context.path, number,
            "filesystem path reaches a std::fs operation without visible canonicalization",
            column=match.start() + 1, language="Rust",
        ))
    return findings


def _literal_valued_names(context: ScanContext) -> frozenset[str]:
    """Names bound to nothing but a string literal.

    Masking blanks a literal's text but keeps its quotes, so ``let raw = "3";``
    reads as ``let raw = "  ";`` -- enough to tell a compile-time constant from
    a runtime value without looking at what the constant said.
    """
    return frozenset(
        match.group(1)
        for match in _LITERAL_BINDING.finditer("\n".join(context.masked))
    )


def _parser_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Deserialization whose failure is converted into a panic.

    ``from_str(input).unwrap()`` is not error handling: malformed input aborts
    the thread. On a request path that turns a parsing boundary into an
    availability boundary, which is worth stating even though a lexical scan
    cannot prove the input is remote.

    A literal receiver is excluded. ``"8080".parse().unwrap()`` cannot fail at
    runtime -- the value is fixed at compile time -- so reporting it says
    nothing a reviewer can act on, and idiomatic Rust is full of it.
    """
    literal_names = _literal_valued_names(context)
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _PARSE_CALLS.search(masked)
        if not match:
            continue
        span = call_span(context, number)
        text = span if span is not None else masked
        if not _PANICKING.search(text):
            continue
        prefix = masked[: match.start()]
        if _LITERAL_RECEIVER.search(prefix):
            continue
        receiver = _RECEIVER_NAME.search(prefix)
        if receiver and receiver.group(1) in literal_names:
            continue
        findings.append(LexicalFinding(
            "parser-boundary", context.path, number,
            "deserialization result is unwrapped or expected, so malformed input panics",
            column=match.start() + 1, language="Rust",
        ))
    return findings


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Query text built by format! or concatenation instead of binding."""
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "Rust",
        "query text is built with format! or concatenation instead of bind parameters",
    )


PACK = LanguagePack(
    name="Rust",
    extensions=frozenset({".rs"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    nested_block_comments=True,
    strings=(StringRule('"', '"', "\\", allow_newline=True),),
    raw_string_fence=re.compile(r"\b(?:b?r)(#*)\""),
    skip_patterns=(
        # Char literals first, then lifetimes. Reversing the order would let
        # `'a'` be read as the lifetime `'a` followed by a dangling quote.
        re.compile(r"'(?:\\.|[^'\\])'"),
        re.compile(r"'(?:static\b|_\b|[A-Za-z_]\w*)"),
    ),
    sinks=(
        SinkRule(
            "subprocess",
            re.compile(r"\bCommand::new\s*\("),
            "std::process::Command creation requires an explicit command boundary",
        ),
        SinkRule(
            "unsafe-block",
            re.compile(r"\bunsafe\s*\{"),
            "unsafe block suspends the compiler's memory-safety guarantee and "
            "requires a stated invariant",
        ),
    ),
    sanitizers=re.compile(r"\.(?:canonicalize|file_name)\s*\("),
    interpolation_markers=("format!", "+"),
    custom_rules=(
        _shell_commands, _path_boundaries, _sql_boundaries,
        _parser_boundaries, _credentials,
    ),
    entry_point_names=frozenset({"main.rs", "lib.rs", "build.rs"}),
)


__all__ = ("PACK",)
