"""Go language pack.

Go gives a lexical scanner unusually good leverage: sinks are reached through
stable, fully-qualified package selectors (``exec.Command``, ``os.ReadFile``,
``db.Query``) rather than through arbitrarily-named methods, and errors are
returned rather than thrown. That makes a discarded error visible in the
assignment form itself, which is why the parser boundary below can be stated
without a control-flow graph.

What the pack still cannot do is prove reachability. Every rule here reports a
boundary that a reviewer must confirm; none of them claims exploitability.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


_TAINT_NAMES = re.compile(
    r"\b(?:user|request|req|input|param|query|arg|name|filename|target|upload)\w*\b", re.I
)
_PATH_SINKS = re.compile(
    r"\b(?:os\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)"
    r"|ioutil\.(?:ReadFile|WriteFile)"
    r"|filepath\.Walk)\s*\("
)
_PATH_NORMALIZERS = re.compile(r"\bfilepath\.(?:Clean|Base|Abs|EvalSymlinks)\s*\(")
_SQL_EXEC = re.compile(
    r"\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare)\s*\("
)
_SQL_CONSTRUCTED = re.compile(r"fmt\.Sprintf\s*\(|[\"`]\s*\+|\+\s*[\"`]")
_UNMARSHAL = re.compile(r"\b(?:json|xml|yaml|toml)\.Unmarshal\s*\(")
# A discarded error: the call is a bare statement, or its only assignment
# target is the blank identifier. Anything bound to a named variable is left
# alone, because the check may legitimately happen on a later line.
_DISCARDED_ERROR = re.compile(r"^\s*(?:_\s*:?=\s*)?(?:json|xml|yaml|toml)\.Unmarshal\s*\(")
_SHELL_COMMAND = re.compile(r"exec\.Command(?:Context)?\s*\(")
_SHELLS = ("sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    """Credential-named bindings, including the ``Key: "value"`` struct form."""
    return credential_findings(context, "Go")


def _shell_commands(context: ScanContext) -> list[LexicalFinding]:
    """``exec.Command`` invoking a shell with a constructed argument.

    ``exec.Command("git", "status")`` runs a program directly and no shell
    parses its arguments, so it is a subprocess boundary and nothing more.
    Handing a constructed string to ``sh -c`` is a different claim: the shell
    will re-parse whatever the string turned out to contain.
    """
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _SHELL_COMMAND.search(masked)
        if not match:
            continue
        raw = context.raw_line(number)
        literals = re.findall(r"\"((?:[^\"\\]|\\.)*)\"", raw)
        if not literals or literals[0].strip().lower() not in _SHELLS:
            continue
        span = call_span(context, number)
        if not _SQL_CONSTRUCTED.search(span if span is not None else masked):
            continue
        findings.append(LexicalFinding(
            "command-injection", context.path, number,
            f"constructed argument reaches a {literals[0]} shell invocation",
            column=match.start() + 1, language="Go",
        ))
    return findings


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Filesystem calls whose path argument shows no visible cleaning."""
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
            "filesystem path reaches an os/ioutil operation without visible filepath.Clean",
            column=match.start() + 1, language="Go",
        ))
    return findings


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Query text built with Sprintf or concatenation instead of bind parameters."""
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "Go",
        # Deliberately avoids the word "placeholder": the contradiction engine
        # treats that word in a co-located finding as an alternative explanation
        # for a credential, so using it here would make any module holding both
        # findings abstain for a fabricated reason.
        "query text is built with Sprintf or concatenation instead of bind parameters",
    )


def _parser_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Unmarshal calls whose returned error is discarded at the call site.

    Go reports decode failure through the return value alone. Dropping it means
    the destination struct keeps whatever it held -- usually a zero value --
    and the program proceeds as though the input had parsed.
    """
    return [
        LexicalFinding(
            "parser-boundary", context.path, number,
            "Unmarshal call discards its error return, so malformed input is "
            "indistinguishable from a zero value",
            column=match.start() + 1, language="Go",
        )
        for number, masked in enumerate(context.masked, 1)
        if _DISCARDED_ERROR.match(masked)
        for match in _UNMARSHAL.finditer(masked)
    ]


PACK = LanguagePack(
    name="Go",
    extensions=frozenset({".go"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    strings=(
        StringRule("`", "`", escape=None, allow_newline=True),
        StringRule('"', '"', "\\"),
    ),
    skip_patterns=(
        # Rune literals. Without this, `'"'` would open a phantom string.
        re.compile(r"'(?:\\.|[^'\\])'"),
    ),
    sinks=(
        SinkRule(
            "subprocess",
            re.compile(r"\bexec\.Command(?:Context)?\s*\("),
            "os/exec process creation requires an explicit command boundary",
        ),
        SinkRule(
            "dynamic-evaluation",
            re.compile(r"\bplugin\.Open\s*\("),
            "plugin.Open loads and executes code chosen at runtime",
        ),
    ),
    sanitizers=re.compile(r"filepath\.(?:Clean|Base|Abs|EvalSymlinks)\s*\("),
    interpolation_markers=("fmt.Sprintf", "+"),
    custom_rules=(
        _shell_commands, _path_boundaries, _sql_boundaries,
        _parser_boundaries, _credentials,
    ),
    entry_point_names=frozenset({"main.go"}),
)


__all__ = ("PACK",)
