"""Shared, language-agnostic lexical scanning primitives.

This module owns the one thing every language pack needs and none of them
should reimplement: turning source text into a *masked* view where comments and
string data are blanked out while code, delimiters, and line geometry survive
untouched. Every detector then matches against that view, so a sink name
written inside a comment or a quoted string can never be reported as an
executable boundary.

Three properties are contractual:

1. **Linear time.** The masker is a single left-to-right pass with no
   backtracking. Minified bundles and unterminated template literals are
   ordinary input, not a denial-of-service vector.
2. **Geometry preserved.** Masking replaces characters with spaces and never
   touches a newline, so line and column numbers in a finding refer to real
   positions in the original file.
3. **No parsing claimed.** Everything here is a bounded lexical heuristic.
   Findings carry that limitation in their evidence rather than borrowing the
   authority of an AST.
"""
from __future__ import annotations

import re
from pathlib import Path

from forge.languages.spec import LanguagePack, LexicalFinding, ScanContext, StringRule


# One assignment form for every supported language: ``x = v``, ``x := v``,
# ``let x = v``. The lookarounds keep comparisons (``==``, ``!=``, ``>=``) from
# being read as assignments, which would let a comparison launder a name into
# the sanitized set.
_ASSIGNMENT = re.compile(r"\b(\w+)\s*(?<![=!<>+\-*/%&|^])(?::=|=)(?!=)([^\n;]*)")


def _match_token(source: str, index: int, tokens: tuple[str, ...]) -> str | None:
    for token in tokens:
        if token and source.startswith(token, index):
            return token
    return None


def _mask_string_literal(
    source: str, out: list[str], start: int, rule: StringRule,
) -> int:
    """Blank one string literal's data and return the index just past it.

    Opening and closing delimiters stay visible: a detector often needs to know
    that an argument *was* a literal (``exec.Command("sh", "-c", cmd)``) even
    though it must not see the literal's text. Interpolation spans are
    preserved in full, because ``${userInput}`` inside a template literal is
    code reaching a sink, not inert data.
    """
    length = len(source)
    index = start + len(rule.open)
    while index < length:
        char = source[index]
        if char == "\n" and not rule.allow_newline:
            # An unterminated single-line literal ends at the newline. Blanking
            # onward would silently erase the rest of the file.
            return index
        if rule.escape and char == rule.escape and index + 1 < length:
            if source[index + 1] != "\n":
                out[index + 1] = " "
            out[index] = " "
            index += 2
            continue
        if rule.preserve is not None:
            preserved = rule.preserve.match(source, index)
            if preserved and preserved.end() > index:
                index = preserved.end()
                continue
        if rule.interpolation is not None and source.startswith(rule.interpolation[0], index):
            index += len(rule.interpolation[0])
            depth = 1
            while index < length and depth:
                if source[index] == "{":
                    depth += 1
                elif source[index] == "}":
                    depth -= 1
                index += 1
            continue
        if source.startswith(rule.close, index):
            if rule.doubled_close_escapes and source.startswith(rule.close * 2, index):
                for offset in range(2 * len(rule.close)):
                    if source[index + offset] != "\n":
                        out[index + offset] = " "
                index += 2 * len(rule.close)
                continue
            return index + len(rule.close)
        if char != "\n":
            out[index] = " "
        index += 1
    return length


def _block_opener(
    source: str, index: int, pairs: tuple[tuple[str, str], ...],
) -> tuple[str, str] | None:
    """Return the block-comment pair opening at ``index``, if any.

    An opener written with a leading newline is *line-anchored*: it only counts
    at the start of a line. The first line of a file has no preceding newline,
    so it is matched there as well -- otherwise a licence header written as a
    Ruby ``=begin`` block at offset zero would be read as code.
    """
    for open_token, close_token in pairs:
        if source.startswith(open_token, index):
            return open_token, close_token
        if (
            index == 0 and open_token.startswith("\n")
            and source.startswith(open_token[1:], 0)
        ):
            return open_token[1:], close_token
    return None


def _heredoc_body_end(source: str, start: int, label: str) -> tuple[int, int]:
    """Return ``(body_end, resume)`` for a heredoc closed by ``label``.

    The body begins on the line after the opener and ends at the first later
    line whose stripped text is the label. Trailing punctuation is tolerated
    because PHP writes ``EOT;`` and Ruby sometimes writes ``SQL)``.
    """
    line_end = source.find("\n", start)
    if line_end < 0:
        return len(source), len(source)
    position = line_end + 1
    while position < len(source):
        end = source.find("\n", position)
        end = len(source) if end < 0 else end
        if source[position:end].strip().rstrip(";,)").strip() == label:
            return position, end
        position = end + 1
    return len(source), len(source)


def mask_source(source: str, pack: LanguagePack) -> list[str]:
    """Return the source's lines with comments and string data blanked out."""
    out = list(source)
    length = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if out[position] != "\n":
                out[position] = " "

    if pack.code_delimiters:
        # Everything outside a code region is markup or prose, never code. A
        # template's HTML must not be scanned for sinks.
        index = 0
        cursor = 0
        while cursor < length:
            opened = min(
                (position for position in
                 (source.find(open_token, cursor) for open_token, _ in pack.code_delimiters)
                 if position >= 0),
                default=-1,
            )
            if opened < 0:
                blank(cursor, length)
                break
            blank(cursor, opened)
            close_token = next(
                close for open_token, close in pack.code_delimiters
                if source.startswith(open_token, opened)
            )
            closed = source.find(close_token, opened)
            cursor = length if closed < 0 else closed + len(close_token)
        source = "".join(out)

    while index < length:
        # Newlines are deliberately *not* skipped early here. A line-anchored
        # block comment declares its opener with a leading newline (Ruby's
        # `=begin`), so the scanner has to be standing on that newline for the
        # opener to match. Skipping ahead made every `=begin` block invisible
        # and its prose was scanned as code.
        skipped = None
        for pattern in pack.skip_patterns:
            match = pattern.match(source, index)
            if match and match.end() > index:
                skipped = match.end()
                break
        if skipped is not None:
            index = skipped
            continue
        marker = _match_token(source, index, pack.line_comments)
        if marker:
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        opened = _block_opener(source, index, pack.block_comments)
        if opened is not None:
            open_token, close_token = opened
            depth = 1
            cursor = index + len(open_token)
            while cursor < length and depth:
                if pack.nested_block_comments and source.startswith(open_token, cursor):
                    depth += 1
                    cursor += len(open_token)
                elif source.startswith(close_token, cursor):
                    depth -= 1
                    cursor += len(close_token)
                else:
                    cursor += 1
            blank(index, cursor)
            index = cursor
            continue
        if pack.heredoc is not None:
            opener = pack.heredoc.match(source, index)
            if opener:
                body_end, resume = _heredoc_body_end(source, opener.end(), opener.group("label"))
                blank(opener.start(), body_end)
                index = resume
                continue
        if pack.raw_string_fence is not None:
            fence = pack.raw_string_fence.match(source, index)
            if fence:
                closer = '"' + fence.group(1)
                closing = source.find(closer, fence.end())
                content_end = length if closing < 0 else closing
                blank(fence.end(), content_end)
                index = length if closing < 0 else closing + len(closer)
                continue
        rule = next((item for item in pack.strings if source.startswith(item.open, index)), None)
        if rule is not None:
            index = _mask_string_literal(source, out, index, rule)
            continue
        index += 1
    return "".join(out).splitlines()


def has_interpolation(text: str, pack: LanguagePack) -> bool:
    """Whether a span shows a value being *constructed* rather than written out.

    A fully literal argument is not evidence of an injectable boundary. This is
    the check that keeps ``exec.Command("ls", "-la")`` out of the findings while
    keeping ``exec.Command(userSuppliedBinary)`` in.
    """
    return any(marker in text for marker in pack.interpolation_markers)


def call_span(context: ScanContext, line_number: int, max_lines: int = 32) -> str | None:
    """Return the masked text of a call that crosses source lines, or ``None``.

    Bounded deliberately: a scan must not walk an entire minified file looking
    for a balancing parenthesis. ``None`` means the call did not close inside
    the bound -- an unresolved boundary, which callers must treat as *not
    proven safe* rather than quietly assume is fine.
    """
    parts: list[str] = []
    depth = 0
    for number in range(line_number, min(len(context.masked), line_number + max_lines - 1) + 1):
        text = context.masked_line(number)
        parts.append(text)
        depth += text.count("(") - text.count(")")
        if number > line_number and depth <= 0:
            return " ".join(parts)
    return None


def span_lines(context: ScanContext, line_number: int, max_lines: int = 32) -> tuple[str, str]:
    """Return the masked and raw text of the call beginning at ``line_number``.

    The masked half is for structure, the raw half for literal values. Unlike
    :func:`call_span` this always returns text, because its callers use it as a
    guard that narrows a candidate rather than as proof the call closed.
    """
    depth = 0
    masked_parts: list[str] = []
    raw_parts: list[str] = []
    for number in range(line_number, min(len(context.masked), line_number + max_lines - 1) + 1):
        masked_parts.append(context.masked_line(number))
        raw_parts.append(context.raw_line(number))
        depth += masked_parts[-1].count("(") - masked_parts[-1].count(")")
        if number > line_number and depth <= 0:
            break
    return " ".join(masked_parts), " ".join(raw_parts)


def argument_zero(text: str, open_index: int) -> str:
    """Return the first argument of the call whose ``(`` is at ``open_index``.

    Which argument matters is the whole question for a query sink. In
    ``db.QueryRow("SELECT name WHERE id = $1", fmt.Sprintf("%s", raw))`` the
    query is a constant and the constructed value is a *bound parameter* --
    the safe form, and the one a whole-call scan reports as an injection.
    """
    depth = 0
    start = open_index + 1
    for index in range(open_index, len(text)):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:index]
        elif char == "," and depth == 1:
            return text[start:index]
    return text[start:]


#: A query sink's first argument has to actually look like a query. Without
#: this, any generic ``execute(...)`` or ``query(...)`` method -- and those
#: names are not reserved for databases -- became a SQL finding as soon as its
#: argument was built with string formatting.
SQL_KEYWORD = re.compile(
    r"\b(?:select|insert\s+into|update|delete\s+from|merge|upsert|create\s+table|drop\s+table|alter\s+table)\b",
    re.I,
)


def sql_findings(
    context: ScanContext,
    call_pattern: re.Pattern[str],
    constructed: re.Pattern[str],
    language: str,
    description: str,
    require_sql_keyword: bool = True,
) -> list[LexicalFinding]:
    """Report query text built by formatting or concatenation instead of binding.

    Three conditions must hold together, and each one removes a class of false
    positive observed against idiomatic code: the call is real code in the
    masked view, its *first* argument shows construction, and the raw text of
    that call actually contains SQL.

    ``require_sql_keyword`` relaxes the third condition for sinks whose *name*
    already proves the argument is SQL. An ORM fragment method such as Rails'
    ``.where`` takes a WHERE clause, not a whole statement, so demanding a
    ``SELECT`` there loses the real injection ``.where("n = '#{param}'")``
    while protecting nothing.
    """
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        match = call_pattern.search(masked)
        if not match:
            continue
        span_masked, span_raw = span_lines(context, number)
        located = call_pattern.search(span_masked) or match
        source = span_masked if call_pattern.search(span_masked) else masked
        open_index = source.find("(", located.end() - 1)
        if open_index < 0:
            continue
        argument = argument_zero(source, open_index)
        if not constructed.search(argument):
            continue
        if require_sql_keyword and not SQL_KEYWORD.search(span_raw):
            continue
        findings.append(LexicalFinding(
            "sql-injection", context.path, number, description,
            column=match.start() + 1, language=language,
        ))
    return findings


def guarded_lines(context: ScanContext, opener: re.Pattern[str]) -> frozenset[int]:
    """Line numbers still enclosed by a brace block that ``opener`` started.

    A bounded structural heuristic over brace depth, not a parser. Its purpose
    is to stop a handler in an *adjacent* function from vouching for an
    unguarded boundary: the block must still be open at the line in question
    for its protection to count. Computed in one pass so a file with many
    candidate sinks stays linear rather than quadratic.
    """
    guarded: set[int] = set()
    depth = 0
    active: list[int] = []
    for number, text in enumerate(context.masked, 1):
        before = depth
        opens = text.count("{")
        closes = text.count("}")
        if opener.search(text):
            active.append(before + 1)
        if any(required <= before + opens for required in active):
            guarded.add(number)
        depth = max(0, depth + opens - closes)
        active = [required for required in active if required <= depth]
    return frozenset(guarded)


def sanitized_names(context: ScanContext) -> frozenset[str]:
    """Names shown to have passed a declared sanitizer, plus what they flow into.

    The closure matters as much as the direct hit: ``base = filepath.Clean(p)``
    followed by ``target = base + "/" + name`` means the sanitizer's evidence is
    still relevant at the sink. Without the fixed point, every real codebase's
    normal indirection would read as unsanitized.
    """
    pack = context.pack
    if pack.sanitizers is None:
        return frozenset()
    masked = "\n".join(context.masked)
    # The sanitizer is searched against the whole assignment, target included:
    # ``safeName = name.replace(...)`` earns its evidence from the naming
    # convention as much as from the call, and dropping the target would lose
    # the common case where the sanitizing intent is spelled in the name.
    assignments = [
        (match.group(1), match.group(0), match.group(2))
        for match in _ASSIGNMENT.finditer(masked)
    ]
    names = {
        target for target, whole, _expression in assignments if pack.sanitizers.search(whole)
    }
    changed = True
    while changed:
        changed = False
        for target, _whole, expression in assignments:
            if target in names:
                continue
            if any(re.search(rf"\b{re.escape(name)}\b", expression) for name in names):
                names.add(target)
                changed = True
    return frozenset(names)


_CREDENTIAL_PLACEHOLDER = re.compile(
    r"^(changeme|change_me|example|placeholder|your[_ -].*|<.*>|\s*)$", re.I
)
# Anchored on the credential-like *stem*, not on a generic identifier. A
# leading unbounded `\w*` would match an entire minified line at every start
# position and then backtrack out of it, which is quadratic; the bounded
# `\w{0,32}` around a rare stem keeps the work per position constant. The
# literal body alternates on disjoint first characters (escape versus
# not-escape) so it cannot backtrack exponentially on an unterminated string.
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(\w{0,32}(?:password|passwd|secret|token|api[_-]?key|credential)\w{0,32})\s*"
    r"(?::\s*[\w:<>\[\]&'*. ]{0,40})?"
    r"(?::=|=|:)\s*"
    r"([\"'`])((?:\\.|(?!\2)[^\\\n])*)\2",
    re.I,
)


def credential_findings(context: ScanContext, language: str) -> list[LexicalFinding]:
    """Credential-named identifiers assigned a non-placeholder string literal.

    Shared by every pack so the same defect reads identically whichever
    language it is written in, and mirrors the Python AST detector's rule.
    Masking blanked the literal's value on purpose, so the value is read from
    the raw line -- but only after the masked line has shown the assignment is
    real code rather than prose inside a comment.
    """
    findings: list[LexicalFinding] = []
    for number, masked in enumerate(context.masked, 1):
        if "=" not in masked and ":" not in masked:
            continue
        for match in _CREDENTIAL_ASSIGNMENT.finditer(context.raw_line(number)):
            name, value = match.group(1), match.group(3)
            if _CREDENTIAL_PLACEHOLDER.match(value):
                continue
            findings.append(LexicalFinding(
                "hardcoded-credential", context.path, number,
                f"non-empty credential-like string assigned to {name}",
                column=match.start() + 1, language=language,
            ))
    return findings


def untainted_names(context: ScanContext, taint: re.Pattern[str]) -> frozenset[str]:
    """Names whose assigned expression shows nothing externally-shaped.

    A variable is not suspicious merely because it is *called* ``target``. What
    matters is what flowed into it: ``target = Path.Combine(root, ConfigName)``
    carries nothing external, while ``target = Path.Combine(userInput, name)``
    does. Without this distinction every conventional destination-path name
    reported as a traversal candidate the moment a normalizer was not visible
    on the same line.

    Only *assigned* names can be cleared. A function parameter has no visible
    origin, so it stays suspicious -- which is the case the rule exists to keep.
    """
    assignments = [
        (match.group(1), match.group(2))
        for match in _ASSIGNMENT.finditer("\n".join(context.masked))
    ]
    tainted = {target for target, expression in assignments if taint.search(expression)}
    changed = True
    while changed:
        changed = False
        for target, expression in assignments:
            if target in tainted:
                continue
            if any(re.search(rf"\b{re.escape(name)}\b", expression) for name in tainted):
                tainted.add(target)
                changed = True
    return frozenset({target for target, _ in assignments} - tainted)


def build_context(pack: LanguagePack, path: str, source: str) -> ScanContext:
    context = ScanContext(
        pack=pack, path=path, source=source,
        masked=mask_source(source, pack), raw=source.splitlines(),
    )
    context.sanitized_names = sanitized_names(context)
    return context


def scan_source(pack: LanguagePack, path: str, source: str) -> list[LexicalFinding]:
    """Run one pack's declared sinks and custom rules over one file.

    Findings are returned in deterministic order -- line, then column, then
    family -- because the audit seal is computed over finding order. An
    iteration order that depends on dictionary or filesystem chance would make
    an identical repository produce a different hash.
    """
    context = build_context(pack, path, source)
    findings: list[LexicalFinding] = []
    for number, text in enumerate(context.masked, 1):
        if not text.strip():
            continue
        for rule in pack.sinks:
            for match in rule.pattern.finditer(text):
                if rule.requires_interpolation:
                    span = call_span(context, number)
                    # An unresolved span is not evidence of a literal argument,
                    # so fall back to the matched line rather than dropping the
                    # candidate on a technicality.
                    if not has_interpolation(span if span is not None else text, pack):
                        continue
                findings.append(LexicalFinding(
                    rule.family, path, number, rule.description,
                    rule.controllability, rule.exploitability,
                    match.start() + 1, pack.name,
                ))
    for rule in pack.custom_rules:
        findings.extend(rule(context))
    return sorted(findings, key=lambda item: (item.line, item.column or 0, item.family))


def read_source(path: Path) -> tuple[str | None, str | None]:
    """Read one candidate file, returning ``(source, examination_reason)``.

    Unreadable and non-UTF-8 files are distinct boundaries and stay distinct.
    Collapsing them would tell a reviewer to fix the wrong thing.
    """
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError:
        return None, "unreadable_file"
    except UnicodeDecodeError:
        return None, "non_utf8_text"


__all__ = (
    "build_context", "call_span", "credential_findings", "guarded_lines",
    "has_interpolation", "mask_source", "read_source", "sanitized_names",
    "scan_source",
)
