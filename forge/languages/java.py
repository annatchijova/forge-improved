"""Java language pack.

Java's high-signal boundaries are reached through stable, fully-qualified
names -- ``Runtime.getRuntime().exec``, ``ObjectInputStream.readObject``,
``Statement.executeQuery`` -- which is what makes a lexical scan useful here
despite having no type information.

Two rules are file-scoped rather than line-scoped, because that is where the
evidence actually lives. XML parser hardening and the presence of a script
engine are properties of a compilation unit, not of the line that happens to
call into them.
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
    r"\bnew\s+File\s*\(|\bPaths\.get\s*\(|\bFiles\.(?:readAllBytes|readAllLines|readString"
    r"|newInputStream|newOutputStream|write|writeString|delete|deleteIfExists|copy)\s*\("
)
_PATH_NORMALIZERS = re.compile(r"\.(?:normalize|toRealPath|getFileName|getCanonicalPath)\s*\(")
_SQL_EXEC = re.compile(r"\.(?:executeQuery|executeUpdate|execute|addBatch)\s*\(")
_SQL_CONSTRUCTED = re.compile(r"\"\s*\+|\+\s*\"|\.concat\s*\(|String\.format\s*\(|\.formatted\s*\(")
# A script engine's `eval` is a data-to-code boundary; every other `eval` in a
# Java file is someone's ordinary method. The file must import the scripting
# API before the call is treated as one.
_SCRIPT_ENGINE_IMPORT = re.compile(r"\bimport\s+javax\.script\.|\bScriptEngineManager\b")
_SCRIPT_EVAL = re.compile(r"\.eval\s*\(")
_XML_FACTORIES = re.compile(
    r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SchemaFactory|TransformerFactory)\s*\.\s*newInstance\s*\("
)
# Any one of these is evidence that the author considered external entities.
_XML_HARDENING = re.compile(
    r"setFeature\s*\(|setProperty\s*\(|FEATURE_SECURE_PROCESSING|setXIncludeAware\s*\(|"
    r"setExpandEntityReferences\s*\(|ACCESS_EXTERNAL_"
)
# The read is the boundary; constructing the stream is only its setup. Matching
# both meant `new ObjectInputStream(in).readObject()` reported twice on one line,
# with different columns, so the runtime's deduplication could not collapse it.
_DESERIALIZE = re.compile(r"\.(?:readObject|readUnshared)\s*\(\s*\)")


def _credentials(context: ScanContext) -> list[LexicalFinding]:
    return credential_findings(context, "Java")


def _sql_boundaries(context: ScanContext) -> list[LexicalFinding]:
    return sql_findings(
        context, _SQL_EXEC, _SQL_CONSTRUCTED, "Java",
        "query text is concatenated or formatted instead of bound to a prepared statement",
    )


def _path_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """File construction whose path shows no visible normalization."""
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
            "filesystem path reaches a File/Files operation without visible normalization",
            column=match.start() + 1, language="Java",
        ))
    return findings


def _script_evaluation(context: ScanContext) -> list[LexicalFinding]:
    """``eval`` on a script engine, only in a file that imports one."""
    if not _SCRIPT_ENGINE_IMPORT.search(context.source):
        return []
    return [
        LexicalFinding(
            "dynamic-evaluation", context.path, number,
            "script engine evaluation crosses a data-to-code boundary",
            column=match.start() + 1, language="Java",
        )
        for number, masked in enumerate(context.masked, 1)
        for match in _SCRIPT_EVAL.finditer(masked)
    ]


def _xml_entity_boundaries(context: ScanContext) -> list[LexicalFinding]:
    """An XML factory built in a file that never configures entity handling.

    XXE is the defect a Java audit is most often asked about, and its evidence
    is an *absence* -- no ``setFeature``, no secure processing, no external
    access restriction anywhere in the unit. Scoping the check to the whole
    file rather than the construction line is what keeps it honest: hardening
    is conventionally applied a few lines below the factory, not on it.
    """
    if _XML_HARDENING.search("\n".join(context.masked)):
        return []
    return [
        LexicalFinding(
            "parser-boundary", context.path, number,
            "XML factory is created with no external-entity or secure-processing "
            "configuration visible in this file",
            column=match.start() + 1, language="Java",
        )
        for number, masked in enumerate(context.masked, 1)
        for match in _XML_FACTORIES.finditer(masked)
    ]


PACK = LanguagePack(
    name="Java",
    extensions=frozenset({".java"}),
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    strings=(
        # Text blocks first: `"""` must not be read as an empty `""` followed by
        # an opening quote.
        StringRule('"""', '"""', "\\", allow_newline=True),
        StringRule('"', '"', "\\"),
    ),
    skip_patterns=(re.compile(r"'(?:\\.|[^'\\])'"),),
    sinks=(
        SinkRule(
            "subprocess",
            re.compile(r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bnew\s+ProcessBuilder\s*\("),
            "process creation requires an explicit command boundary",
        ),
        SinkRule(
            "unsafe-deserialization",
            _DESERIALIZE,
            "Java native deserialization reconstructs arbitrary object graphs from its input",
        ),
    ),
    sanitizers=re.compile(r"\.(?:normalize|toRealPath|getFileName|getCanonicalPath)\s*\("),
    interpolation_markers=("+", "String.format", ".formatted"),
    custom_rules=(
        _path_boundaries, _sql_boundaries, _script_evaluation,
        _xml_entity_boundaries, _credentials,
    ),
    entry_point_names=frozenset({"Main.java", "Application.java"}),
    entry_point_patterns=(
        # Spring, Jakarta and JUnit all dispatch into these; nothing imports them.
        re.compile(r"(?:^|/)\w*(?:Controller|Application|Resource|Servlet|Filter|Listener|Job|Task|Test|Tests|IT)\.java$"),
        re.compile(r"^(?:src/test|test|tests)/"),
    ),
)


__all__ = ("PACK",)
