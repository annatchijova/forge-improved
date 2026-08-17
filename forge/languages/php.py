"""PHP language pack.

PHP is the one language here where a source file is *not* code by default. A
template is HTML until ``<?php`` opens, and prose in that markup must never be
scanned for sinks -- so the pack declares code delimiters and the masker blanks
everything outside them.

Inside a double-quoted string, ``$name`` and ``{$expr}`` are code. Both are
preserved through masking, which is what makes an interpolated query visible as
a value reaching a sink rather than as inert text. Nowdocs (``<<<'EOT'``) do not
interpolate, but the masker blanks heredoc bodies either way, so the
distinction costs nothing here.

The include family is PHP-specific and high-signal: ``include $page`` resolves
a path at runtime and then *executes* it, which is a code boundary rather than
a file-read boundary.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings, untainted_names
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


# The leading `$` is deliberately *not* captured. Assignment targets are
# recorded without their sigil, so a pattern that returned `$target` while the
# sanitized and untainted sets held `target` could never match them up -- and a
# provably-cleared path would still be reported. `$` is not a word character,
# so `\b` already anchors correctly against `$_GET` and `$target` alike.
_TAINT_NAMES = re.compile(
    r"\b(?:_GET|_POST|_REQUEST|_COOKIE|_FILES|user|request|req|input|param|query"
    r"|arg|name|filename|target|upload)\w*\b", re.I
)
_PATH_SINKS = re.compile(
    r"\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|rename|copy"
    r"|opendir|scandir)\s*\("
)
_PATH_NORMALIZERS = re.compile(r"\b(?:basename|realpath)\s*\(")
_SQL_EXEC = re.compile(
    r"\b(?:mysqli_query|mysql_query|pg_query|sqlsrv_query)\s*\(|->(?:query|exec|unsafeQuery)\s*\("
)
_SQL_CONSTRUCTED = re.compile(r"\$\w|\{\$|['\"]\s*\.|\.\s*['\"]|sprintf\s*\(")
# `include $page` resolves a path at runtime and then executes it: a code
# boundary, not a file-read one. A literal include is ordinary composition.
_DYNAMIC_INCLUDE = re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "PHP")


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "PHP",
        "query text is interpolated or concatenated instead of bound to a prepared statement",
    )


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Filesystem calls whose path shows no visible basename or realpath."""
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
            "filesystem path reaches a file operation without visible basename or realpath",
            column=match.start() + 1, language="PHP",
        ))
    return findings


def _dynamic_includes(context: ScanContext) -> list[LexicalFinding]:
    """``include``/``require`` of a runtime-resolved path."""
    return [
        LexicalFinding(
            "dynamic-evaluation", context.path, number,
            "include/require resolves its target at runtime and then executes it",
            column=match.start() + 1, language="PHP",
        )
        for number, masked in enumerate(context.masked, 1)
        for match in _DYNAMIC_INCLUDE.finditer(masked)
    ]


PACK = LanguagePack(
    name="PHP",
    extensions=frozenset({".php", ".phtml"}),
    line_comments=("//", "#"),
    block_comments=(("/*", "*/"),),
    code_delimiters=(("<?php", "?>"), ("<?=", "?>")),
    strings=(
        StringRule(
            '"', '"', "\\",
            # `$name`, `$obj->prop`, `$arr['k']` and `{$expr}` are all code.
            preserve=re.compile(r"\{\$[^}\n]*\}|\$\w+(?:->\w+|\[[^\]\n]*\])*"),
        ),
        StringRule("'", "'", "\\"),
    ),
    heredoc=re.compile(r"<<<\s*(?P<q>['\"]?)(?P<label>[A-Za-z_]\w*)(?P=q)"),
    sinks=(
        SinkRule(
            "dynamic-evaluation",
            re.compile(r"(?<![\w$>])(?:eval|create_function|assert)\s*\("),
            "dynamic code evaluation crosses a data-to-code boundary",
        ),
        SinkRule(
            "subprocess",
            re.compile(
                r"(?<![\w$>])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(|`"
            ),
            "shell or process execution requires an explicit command boundary",
        ),
        SinkRule(
            "unsafe-deserialization",
            re.compile(r"(?<![\w$>])unserialize\s*\("),
            "unserialize reconstructs arbitrary PHP objects from its input",
        ),
    ),
    sanitizers=_PATH_NORMALIZERS,
    interpolation_markers=("$", "."),
    custom_rules=(_path_boundaries, _sql_boundaries, _dynamic_includes, _credentials),
    syntax_commands={extension: ("php", "-l") for extension in (".php", ".phtml")},
    entry_point_names=frozenset({"index.php", "index.phtml"}),
    entry_point_patterns=(
        re.compile(r"(?:^|/)\w*Controller\.php$"),
        re.compile(r"^(?:public|web|routes|tests?)/"),
    ),
)


__all__ = ("PACK",)
