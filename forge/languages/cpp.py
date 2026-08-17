"""C and C++ language pack.

One pack covers both because ``.h`` belongs to neither exclusively, and a
scanner that had to decide which language a header was written in before
reading it would guess more often than it resolved.

What a lexical view can and cannot see here is unusually lopsided. The defects
C is most known for -- use-after-free, double free, out-of-bounds indexing --
need types, lifetimes and a call graph, and none of that survives masking, so
this pack does not pretend to look for them. What it does see is the family of
*unbounded* standard-library calls whose danger is inherent to the function
chosen rather than to how it was used: ``strcpy`` cannot be made safe by its
arguments, which is exactly why it reads well lexically.

Connectivity works differently too. A translation unit is compiled by the build
system, not included by another file, so ``.c`` and ``.cpp`` have no callers by
construction and are treated as entry points. Headers are the files that get
included, and a header nothing includes is genuinely orphaned.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings, untainted_names
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


_TAINT_NAMES = re.compile(
    r"\b(?:user|request|req|input|param|query|arg|argv|name|filename|target|upload|buf)\w*\b",
    re.I,
)
_PATH_SINKS = re.compile(r"\b(?:fopen|freopen|open|openat|remove|unlink|rename)\s*\(")
_PATH_NORMALIZERS = re.compile(r"\b(?:realpath|basename)\s*\(")
_SQL_EXEC = re.compile(r"\b(?:mysql_query|mysql_real_query|sqlite3_exec|PQexec)\s*\(")
_SQL_CONSTRUCTED = re.compile(r"sprintf\s*\(|snprintf\s*\(|strcat\s*\(|\"\s*\+|\+\s*\"")
# These cannot be made safe by their arguments: none of them takes a
# destination bound, so the danger is inherent to the function chosen. That is
# what makes them read well lexically, where a bounds bug does not.
_UNBOUNDED = re.compile(
    r"(?<![\w>.])(?:strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy|wcscat)\s*\("
)
_SHELL_COMMAND = re.compile(r"(?<![\w>.])(?:system|popen)\s*\(")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "C/C++")


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "C/C++",
        "query text is built with sprintf or strcat instead of a bound parameter",
    )


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """File operations whose path shows no visible realpath or basename."""
    benign = untainted_names(context, _TAINT_NAMES)
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _PATH_SINKS.search(masked)
        if not match:
            continue
        span = call_span(context, number)
        text = span if span is not None else masked
        names = set(_TAINT_NAMES.findall(text)) - benign
        if not names - set(context.sanitized_names) or _PATH_NORMALIZERS.search(text):
            continue
        findings.append(LexicalFinding(
            "path-traversal", context.path, number,
            "filesystem path reaches a file operation without visible realpath or basename",
            column=match.start() + 1, language="C/C++",
        ))
    return findings


def _shell_commands(context: ScanContext) -> list[LexicalFinding]:
    """``system``/``popen`` given a value that was built rather than written.

    A literal command is a subprocess boundary and is reported as one by the
    sink table. Handing over a constructed string is the stronger claim: a
    shell re-parses whatever the buffer turned out to contain.
    """
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _SHELL_COMMAND.search(masked)
        if not match:
            continue
        span = call_span(context, number)
        text = span if span is not None else masked
        argument = text[match.end():]
        # A quoted literal argument is the safe form; anything else reaching a
        # shell is a value this scan cannot account for.
        if re.match(r'\s*"', argument):
            continue
        findings.append(LexicalFinding(
            "command-injection", context.path, number,
            "a non-literal command string reaches a shell that will re-parse it",
            column=match.start() + 1, language="C/C++",
        ))
    return findings


PACK = LanguagePack(
    name="C/C++",
    extensions=frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    strings=(StringRule('"', '"', "\\"),),
    # C++11 raw strings choose their own delimiter and close with `)tag"`,
    # unlike Rust's `"##`, so the pack declares the closing shape.
    raw_string_fence=re.compile(r'\b(?:u8|u|U|L)?R"(?P<d>[^\s()\\]{0,16})\('),
    raw_string_close='){fence}"',
    skip_patterns=(
        # Character literals, including the escaped and multi-byte spellings.
        re.compile(r"'(?:\\(?:[abfnrtv0'\"\\?]|x[0-9A-Fa-f]+|[0-7]{1,3})|[^'\\])'"),
    ),
    sinks=(
        SinkRule(
            "subprocess",
            re.compile(r"(?<![\w>.])(?:system|popen|execl|execlp|execle|execv|execvp|execve)\s*\("),
            "process or shell execution requires an explicit command boundary",
        ),
        SinkRule(
            "unbounded-copy",
            _UNBOUNDED,
            "this standard-library call takes no destination bound, so the "
            "destination size is not checked by the call itself",
        ),
        SinkRule(
            "dynamic-evaluation",
            re.compile(r"(?<![\w>.])(?:dlopen|dlsym|LoadLibrary[AW]?|GetProcAddress)\s*\("),
            "code is loaded and resolved at runtime, crossing a data-to-code boundary",
        ),
    ),
    sanitizers=_PATH_NORMALIZERS,
    interpolation_markers=("sprintf", "strcat", "+"),
    custom_rules=(_path_boundaries, _sql_boundaries, _shell_commands, _credentials),
    entry_point_names=frozenset({"main.c", "main.cpp", "main.cc"}),
    entry_point_patterns=(
        # A translation unit is compiled by the build system, never included by
        # another source file, so it has no caller by construction. Headers are
        # the files that get included, and an unincluded header is genuinely
        # orphaned. Detecting a `.c` that no build target compiles would mean
        # reading the Makefile or CMakeLists, which this pack does not do.
        re.compile(r"\.(?:c|cpp|cc|cxx)$"),
    ),
)


__all__ = ("PACK",)
