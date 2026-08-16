"""JavaScript and TypeScript language pack.

This is the pack the ``web_auditor`` agent runs. It is deliberately not a
JavaScript parser: it scans masked source for a small set of high-signal
boundaries and reports CODE FACTs, never exploitability, because no
JavaScript induction harness exists to reproduce them.

Two masking behaviours are specific to this language and matter to the
results. Template literals keep their ``${...}`` substitutions visible,
because an interpolated value reaching ``readFile`` is code flowing to a sink
rather than inert text. Regular-expression literals are consumed as literals
so a character class such as ``/[^"']/`` cannot open a phantom string and
blank the rest of the file.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, guarded_lines, sql_findings
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


# Identifier stems that conventionally carry externally-supplied values. This
# is a naming heuristic and nothing more: it is why every finding below stays
# an observation rather than a claim about reachability.
_TAINT_NAMES = re.compile(r"\b(?:user|request|req|input|path|file|name)\w*\b", re.I)
_PATH_SINKS = re.compile(r"\b(?:readFile|readFileSync|writeFile|writeFileSync|unlink|rm)\s*\(")
_PATH_NORMALIZERS = re.compile(r"\b(?:resolve|normalize|basename)\s*\(")
_TRY_BLOCK = re.compile(r"\btry\s*\{")
_JSON_PARSE = re.compile(r"\bJSON\.parse\s*\(")
_SQL_EXEC = re.compile(r"\.(?:query|execute)\s*\(")
_SQL_CONSTRUCTED = re.compile(r"\$\{|['\"`]\s*\+|\+\s*['\"`]")

# ``child_process`` reached through a destructured or default import. The
# module name lives inside a string literal, so these run against raw source
# only after the masked view has confirmed the line is real import syntax.
_REQUIRE_DESTRUCTURED = re.compile(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"]child_process['\"]\s*\)"
)
_IMPORT_DESTRUCTURED = re.compile(
    r"import\s*\{([^}]*)\}\s*from\s*['\"]child_process['\"]"
)
_EXEC_NAMES = ("exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "JavaScript/TypeScript")


def _child_process_aliases(context: ScanContext) -> set[str]:
    """Names bound to ``child_process`` execution functions by an import."""
    aliases: set[str] = set()
    for number, masked in enumerate(context.masked, 1):
        if "require" not in masked and "import" not in masked:
            continue
        raw = context.raw_line(number)
        for pattern in (_REQUIRE_DESTRUCTURED, _IMPORT_DESTRUCTURED):
            match = pattern.search(raw)
            if not match:
                continue
            for entry in match.group(1).split(","):
                original, _, alias = entry.partition(":")
                bound = (alias or original).strip()
                if original.strip() in _EXEC_NAMES and bound:
                    aliases.add(bound)
    return aliases


def _destructured_subprocess(context: ScanContext) -> list[LexicalFinding]:
    """Execution calls made through a destructured ``child_process`` import.

    Requiring the ``child_process.`` prefix alone would miss the idiomatic
    ``const { exec } = require("child_process")`` form, while flagging a bare
    ``exec(`` would report every unrelated ``db.exec(...)``. Binding the name to
    its import keeps both errors out.
    """
    aliases = _child_process_aliases(context)
    if not aliases:
        return []
    pattern = re.compile(r"(?<![\w.])(" + "|".join(sorted(map(re.escape, aliases))) + r")\s*\(")
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        if "require" in masked or "import" in masked:
            continue
        for match in pattern.finditer(masked):
            findings.append(LexicalFinding(
                "subprocess", context.path, number,
                f"{match.group(1)} imported from child_process executes a command boundary",
                column=match.start() + 1, language="JavaScript/TypeScript",
            ))
    return findings


def _parser_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """``JSON.parse`` with no try block still open at the call site."""
    guarded = guarded_lines(context, _TRY_BLOCK)
    return [
        LexicalFinding(
            "parser-boundary", context.path, number,
            "JSON.parse call has no nearby visible try/catch boundary",
            column=match.start() + 1, language="JavaScript/TypeScript",
        )
        for number, masked in enumerate(context.masked, 1)
        if number not in guarded
        for match in _JSON_PARSE.finditer(masked)
    ]


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Filesystem calls whose path argument shows no visible normalization.

    The multiline branch is the honest half of this rule. When the call spans
    lines and no normalizer is visible anywhere in the span, lexical scope
    cannot prove either safety or exposure, so the finding says exactly that
    instead of asserting a traversal.
    """
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = _PATH_SINKS.search(masked)
        if not match:
            continue
        names = set(_TAINT_NAMES.findall(masked))
        span = call_span(context, number)
        if span is not None and span != masked:
            span_names = set(_TAINT_NAMES.findall(span))
            if span_names and not _PATH_NORMALIZERS.search(span):
                findings.append(LexicalFinding(
                    "path-traversal", context.path, number,
                    "multiline filesystem path boundary requires verification; "
                    "lexical scope cannot prove sanitization",
                    column=match.start() + 1, language="JavaScript/TypeScript",
                ))
                continue
        # ``path`` is usually the imported path namespace (path.join,
        # path.resolve), not an attacker-controlled value. Keep it only when it
        # also appears as a bare argument, which preserves ``readFile(path)``
        # without flagging every local join.
        if "path" in names and not re.search(r"\bpath\s*(?:[,)])", masked):
            names.discard("path")
        if names - set(context.sanitized_names) and not _PATH_NORMALIZERS.search(masked):
            findings.append(LexicalFinding(
                "path-traversal", context.path, number,
                "filesystem path reaches a file operation without visible normalization",
                column=match.start() + 1, language="JavaScript/TypeScript",
            ))
    return findings


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """Query execution built by interpolation or concatenation, not binding."""
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "JavaScript/TypeScript",
        # See the note in the Go pack: "placeholder" is a reserved word for the
        # contradiction engine and must stay out of finding text.
        "query text is interpolated or concatenated instead of parameter-bound",
    )


PACK = LanguagePack(
    name="JavaScript/TypeScript",
    extensions=frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    strings=(
        StringRule("`", "`", "\\", allow_newline=True, interpolation=("${", "}")),
        StringRule("'", "'", "\\"),
        StringRule('"', '"', "\\"),
    ),
    skip_patterns=(
        # A regular-expression literal, recognized only where a division
        # operator cannot appear. Consuming it whole stops a character class
        # from being read as a quote. The three alternatives start with
        # disjoint characters (escape, bracket, anything else) so an
        # unterminated literal fails linearly instead of backtracking.
        re.compile(r"(?<=[=(,:\[!&|?+;{}\s])/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*"),
    ),
    sinks=(
        SinkRule(
            "dynamic-evaluation",
            re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
            "dynamic code evaluation crosses a data-to-code boundary",
        ),
        SinkRule(
            "subprocess",
            re.compile(
                r"\bchild_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("
            ),
            "child_process execution call requires an explicit command boundary",
        ),
    ),
    # A path normalizer, or a ``.replace`` whose neighbourhood names a
    # path-shaped subject (a character class, a separator, a slug). The gap
    # around ``.replace`` is bounded rather than an unanchored lookahead: an
    # unbounded one rescans the whole line at every start position, which turns
    # a single minified line into quadratic work.
    sanitizers=re.compile(
        r"(?:\w+\.)?(?:basename|resolve|normalize)\s*\("
        r"|(?:\[\^|separator|slash|path|name|slug)[^\n]{0,200}?\.replace\s*\("
        r"|\.replace\s*\([^\n]{0,200}?(?:\[\^|separator|slash|path|name|slug)",
        re.I,
    ),
    interpolation_markers=("${", "+"),
    custom_rules=(
        _destructured_subprocess, _parser_boundaries, _path_boundaries,
        _sql_boundaries, _credentials,
    ),
    entry_point_names=frozenset({"index.js", "index.ts", "main.js", "main.ts", "server.js", "server.ts"}),
)


__all__ = ("PACK",)
