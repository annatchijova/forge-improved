"""Declarative description of one source language for the lexical engine.

A language pack is data, not an agent. It states how a language delimits
comments and string literals, which extensions belong to it, and which
detector rules the shared engine should run over its masked source. Adding a
language is therefore a specification, not a new scanner.

The engine that consumes these specs is deliberately not a parser. Every
finding it produces is a lexical observation over masked source text, and the
packs are written so that the boundary is visible in the emitted evidence
rather than implied by a confident-sounding description.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class StringRule:
    """One string-literal form: how it opens, closes, and escapes.

    ``escape`` is ``None`` for raw forms (Go backticks, Rust ``r"..."``) where a
    backslash is an ordinary character. ``interpolation`` names a substitution
    span whose contents are *code*, not data: masking must preserve it so a
    detector can still see the expression reaching a sink. That is what makes
    ``readFile(`${base}/${name}`)`` observable instead of being blanked away
    with the surrounding template text.
    """

    open: str
    close: str
    escape: str | None = "\\"
    allow_newline: bool = False
    interpolation: tuple[str, str] | None = None


@dataclass(frozen=True)
class SinkRule:
    """A high-signal lexical boundary the engine reports when matched.

    ``pattern`` runs against masked source, so it can never match text that
    lived inside a string literal or a comment. ``requires_interpolation``
    restricts the rule to matches whose call span shows a constructed value
    (concatenation, interpolation, formatting); a fully literal argument is not
    evidence of an injectable boundary and is dropped before it becomes noise.
    """

    family: str
    pattern: re.Pattern[str]
    description: str
    requires_interpolation: bool = False
    controllability: str = "UNDETERMINED"
    exploitability: str = "NOT_ASSESSED"


@dataclass(frozen=True)
class LanguagePack:
    """Everything the shared engine needs to scan one language.

    ``custom_rules`` is the escape hatch for boundaries that no regex over a
    single masked line can express honestly -- an unchecked Go error return, a
    Rust ``unwrap`` on a parse, a JavaScript ``JSON.parse`` with no enclosing
    handler. Each callable receives the whole masked file and returns findings,
    which keeps the pattern table readable instead of encoding control flow in
    a regex.
    """

    name: str
    extensions: frozenset[str]
    line_comments: tuple[str, ...] = ()
    block_comments: tuple[tuple[str, str], ...] = ()
    nested_block_comments: bool = False
    strings: tuple[StringRule, ...] = ()
    # Matched at the cursor; group 1 must be the hash fence so the engine can
    # find the matching close (Rust ``r##"..."##``).
    raw_string_fence: re.Pattern[str] | None = None
    # Matched at the cursor and consumed verbatim, before any string rule is
    # tried. This is how a language keeps the masker away from tokens that
    # merely look like a quote: Rust lifetimes and Go rune literals must not
    # open a string, and a JavaScript regular-expression literal must not have
    # its bracket class mistaken for one.
    skip_patterns: tuple[re.Pattern[str], ...] = ()
    sinks: tuple[SinkRule, ...] = ()
    sanitizers: re.Pattern[str] | None = None
    interpolation_markers: tuple[str, ...] = ()
    custom_rules: tuple[Callable[["ScanContext"], list["LexicalFinding"]], ...] = ()
    entry_point_names: frozenset[str] = frozenset()

    def owns(self, suffix: str) -> bool:
        return suffix.lower() in self.extensions


@dataclass(frozen=True)
class LexicalFinding:
    """One observation from the lexical engine.

    The field names deliberately mirror ``SecurityFinding`` so the runtime can
    canonicalize agent output through one path. ``exploitability`` defaults to
    ``NOT_ASSESSED`` and packs are not permitted to raise it: a lexical scan
    has no induction harness behind it, so claiming exploitability would be an
    assertion the evidence cannot carry.
    """

    family: str
    path: str
    line: int
    description: str
    controllability: str = "UNDETERMINED"
    exploitability: str = "NOT_ASSESSED"
    column: int | None = None
    language: str = ""


@dataclass
class ScanContext:
    """Masked, line-indexed view of one source file handed to every rule."""

    pack: LanguagePack
    path: str
    source: str
    masked: list[str]
    raw: list[str] = field(default_factory=list)
    sanitized_names: frozenset[str] = field(default_factory=frozenset)

    def masked_line(self, number: int) -> str:
        """Return the 1-indexed masked line, or an empty line when past the end."""
        return self.masked[number - 1] if 1 <= number <= len(self.masked) else ""

    def raw_line(self, number: int) -> str:
        """Return the 1-indexed unmasked line.

        Only for rules that must read a literal's *value* (is argument zero
        ``"sh"``?) after the masked view has already established that the match
        is real code. Matching sinks against this view would let a quoted
        string claim to be an executable boundary.
        """
        return self.raw[number - 1] if 1 <= number <= len(self.raw) else ""


__all__ = ("LanguagePack", "LexicalFinding", "ScanContext", "SinkRule", "StringRule")
