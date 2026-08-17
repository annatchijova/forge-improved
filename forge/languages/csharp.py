"""C# language pack.

C# has the richest string syntax of any pack here: verbatim strings (``@"..."``)
where a backslash is an ordinary character and a doubled quote is an escaped
one, interpolated strings (``$"...{expr}..."``) whose substitutions are code
rather than data, and the two combined in either order (``$@"..."`` /
``@$"..."``). All four are declared, longest opener first, so the masker cannot
mistake one for another and blank the remainder of a file.
"""
from __future__ import annotations

import re

from forge.languages.engine import call_span, credential_findings, sql_findings, untainted_names
from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, SinkRule, StringRule


# `path` is deliberately absent: in both languages `Path`/`Paths` is the
# standard namespace, so including it made every `Path.Combine(...)` and
# `Paths.get(...)` look like a user-supplied value.
_TAINT_NAMES = re.compile(
    r"\b(?:user|request|req|input|param|query|arg|name|filename|target|upload)\w*\b", re.I
)
_PATH_SINKS = re.compile(
    r"\bFile\.(?:ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|Open|OpenRead"
    r"|OpenWrite|Create|Delete|Copy|Move)\s*\(|\bnew\s+FileStream\s*\("
)
_PATH_NORMALIZERS = re.compile(r"\bPath\.(?:GetFileName|GetFullPath)\s*\(")
_SQL_EXEC = re.compile(
    r"\bnew\s+SqlCommand\s*\(|\.(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar"
    r"|FromSqlRaw|ExecuteSqlRaw)\s*\("
)
_SQL_CONSTRUCTED = re.compile(r"\{|\"\s*\+|\+\s*\"|string\.Format\s*\(|\.Append\s*\(")
# BinaryFormatter and friends reconstruct arbitrary object graphs. The type name
# has to appear in the file for a bare `.Deserialize(` to count, because
# `Deserialize` is also how every safe JSON library spells its entry point.
_UNSAFE_SERIALIZERS = re.compile(
    r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|SoapFormatter)\b"
)
_DESERIALIZE_CALL = re.compile(r"\.Deserialize\s*\(")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "C#")


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "C#",
        "query text is interpolated or concatenated instead of bound to a command parameter",
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
            "filesystem path reaches a File operation without visible normalization",
            column=match.start() + 1, language="C#",
        ))
    return findings


def _unsafe_deserialization(context: ScanContext) -> list[LexicalFinding]:
    """``Deserialize`` on a formatter that reconstructs arbitrary object graphs.

    Restricted to files naming one of those formatters. ``Deserialize`` on its
    own is how every safe JSON library spells its entry point, so matching the
    call alone would report the safe majority.
    """
    if not _UNSAFE_SERIALIZERS.search("\n".join(context.masked)):
        return []
    return [
        LexicalFinding(
            "unsafe-deserialization", context.path, number,
            "native .NET deserialization reconstructs arbitrary object graphs from its input",
            column=match.start() + 1, language="C#",
        )
        for number, masked in enumerate(context.masked, 1)
        for match in _DESERIALIZE_CALL.finditer(masked)
    ]


PACK = LanguagePack(
    name="C#",
    extensions=frozenset({".cs"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    strings=(
        # Longest opener first. `$@"` and `@$"` are both legal spellings of a
        # verbatim interpolated string and must be tried before `@"` or `$"`.
        StringRule('$@"', '"', escape=None, allow_newline=True,
                   interpolation=("{", "}"), doubled_close_escapes=True),
        StringRule('@$"', '"', escape=None, allow_newline=True,
                   interpolation=("{", "}"), doubled_close_escapes=True),
        StringRule('@"', '"', escape=None, allow_newline=True, doubled_close_escapes=True),
        StringRule('$"', '"', "\\", interpolation=("{", "}")),
        StringRule('"', '"', "\\"),
    ),
    skip_patterns=(re.compile(r"'(?:\\.|[^'\\])'"),),
    sinks=(
        SinkRule(
            "subprocess",
            re.compile(r"\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\("),
            "process creation requires an explicit command boundary",
        ),
    ),
    sanitizers=_PATH_NORMALIZERS,
    interpolation_markers=("{", "+", "string.Format"),
    custom_rules=(_path_boundaries, _sql_boundaries, _unsafe_deserialization, _credentials),
    entry_point_names=frozenset({"Program.cs", "Startup.cs"}),
    entry_point_patterns=(
        re.compile(r"(?:^|/)\w*(?:Controller|Hub|Worker|Middleware|Migration|Tests?)\.cs$"),
        re.compile(r"^(?:tests?|Migrations)/"),
    ),
)


__all__ = ("PACK",)
