"""Ruby language pack.

Ruby is the densest lexical surface of any pack here, and most of the work is
in the masker rather than the rules. Backticks *execute* rather than quote,
``#{}`` interpolation makes a double-quoted string a code carrier, heredocs
routinely hold SQL and shell text, ``=begin``/``=end`` opens a block comment
nothing else uses, and a symbol (``:name``) or a character literal (``?a``)
must not be read as an unterminated quote.

The families here are the ones a masked view can honestly support. Ruby's
metaprogramming means a great deal of behaviour is unreachable to any lexical
scan, which is why the pack reports boundaries and never claims reachability.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings, untainted_names
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


_TAINT_NAMES = re.compile(
    r"\b(?:user|request|req|input|param|params|query|arg|name|filename|target|upload)\w*\b", re.I
)
_PATH_SINKS = re.compile(
    r"\b(?:File\.(?:open|read|readlines|write|delete|unlink|new)"
    r"|IO\.(?:read|readlines|write)"
    r"|FileUtils\.(?:rm|rm_rf|cp|mv))\s*[\(\s]"
)
_PATH_NORMALIZERS = re.compile(r"\bFile\.(?:basename|expand_path|realpath)\s*\(")
# Two kinds of query sink. A raw one takes a whole statement, and its method
# name is generic enough that the argument has to be shown to contain SQL. An
# ORM fragment method takes a clause, not a statement, and its own name is the
# proof -- `.where` never receives anything but SQL.
_SQL_EXEC = re.compile(
    r"\.(?:execute|find_by_sql|select_all|select_values|exec_query)\s*\("
)
_SQL_FRAGMENT = re.compile(r"\.(?:where|having|order|group|joins|pluck)\s*\(")
# `#{` survives masking, so an interpolated query is visible as code reaching
# the call rather than as inert text.
_SQL_CONSTRUCTED = re.compile(r"#\{|[\"']\s*\+|\+\s*[\"']|%\s*\[")
_UNSAFE_LOAD = re.compile(r"\bMarshal\.load\s*\(|\b(?:YAML|Psych)\.(?:load|load_file)\s*\(")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "Ruby")


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    description = (
        "query text is interpolated or concatenated instead of bound to a query parameter"
    )
    return (
        sql_findings(context, _SQL_EXEC, _SQL_CONSTRUCTED, "Ruby", description)
        + sql_findings(
            context, _SQL_FRAGMENT, _SQL_CONSTRUCTED, "Ruby", description,
            require_sql_keyword=False,
        )
    )


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """File operations whose path shows no visible normalization."""
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
            "filesystem path reaches a File/IO operation without visible expansion",
            column=match.start() + 1, language="Ruby",
        ))
    return findings


def _unsafe_deserialization(context: ScanContext) -> list[LexicalFinding]:
    """``Marshal.load`` and unsafe YAML loads reconstruct arbitrary objects.

    ``YAML.safe_load`` is deliberately excluded by the pattern rather than
    filtered afterwards: it is the fixed form, and reporting it would tell a
    reviewer to undo the correct choice.
    """
    return [
        LexicalFinding(
            "unsafe-deserialization", context.path, number,
            "deserialization reconstructs arbitrary Ruby objects from its input",
            column=match.start() + 1, language="Ruby",
        )
        for number, masked in enumerate(context.masked, 1)
        for match in _UNSAFE_LOAD.finditer(masked)
    ]


PACK = LanguagePack(
    name="Ruby",
    extensions=frozenset({".rb", ".rake"}),
    line_comments=("#",),
    # `=begin`/`=end` are only comment markers at column zero. The masker tries
    # block openers at every position, so the newline prefix anchors them.
    block_comments=(("\n=begin", "\n=end"),),
    strings=(
        # Backticks execute a shell command. Masking the body keeps its text
        # from being read as Ruby, while the surviving delimiters let the
        # subprocess sink below still see the call.
        StringRule("`", "`", "\\", allow_newline=True, interpolation=("#{", "}")),
        StringRule('"', '"', "\\", interpolation=("#{", "}")),
        StringRule("'", "'", "\\"),
    ),
    heredoc=re.compile(r"<<[-~]?(?P<q>['\"]?)(?P<label>[A-Z_][A-Z_0-9]*)(?P=q)"),
    skip_patterns=(
        # A character literal (`?a`) and a symbol (`:name`, `:"quoted"`) both
        # carry a quote-adjacent shape that must not open a literal.
        re.compile(r"\?(?:\\[a-zA-Z]|\w)(?![\w'\"])"),
        re.compile(r"(?<![:\w]):[A-Za-z_]\w*[?!]?"),
    ),
    sinks=(
        SinkRule(
            "dynamic-evaluation",
            re.compile(r"\beval\s*[\(\s]|\b(?:instance|class|module)_eval\s*[\(\s{]"),
            "dynamic code evaluation crosses a data-to-code boundary",
        ),
        SinkRule(
            "subprocess",
            re.compile(
                r"(?<![\w.])(?:system|exec|spawn)\s*\(|`|%x[\(\[{]"
                r"|\bIO\.popen\s*\(|\bOpen3\.(?:capture\d|popen\d)\s*\("
            ),
            "shell or process execution requires an explicit command boundary",
        ),
    ),
    sanitizers=_PATH_NORMALIZERS,
    interpolation_markers=("#{", "+"),
    custom_rules=(_path_boundaries, _sql_boundaries, _unsafe_deserialization, _credentials),
    syntax_commands={extension: ("ruby", "-c") for extension in (".rb", ".rake")},
    entry_point_names=frozenset({"application.rb", "config.ru", "Rakefile"}),
    entry_point_patterns=(
        # Rails resolves these by convention; no file requires them.
        re.compile(r"^app/(?:controllers|jobs|mailers|channels|helpers|views)/"),
        re.compile(r"^(?:config|db/migrate|spec|test|lib/tasks)/"),
        re.compile(r"_(?:spec|test)\.rb$"),
    ),
)


__all__ = ("PACK",)
