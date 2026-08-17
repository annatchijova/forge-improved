"""Optional syntax verification for lexically-scanned languages.

Python source is parsed before it is analysed, so a file FORGE cannot parse
lands in the ``syntax_error`` bucket and blocks the audit's completeness claim.
No lexical language had any equivalent: a masked-text scan reads a malformed
file exactly as happily as a valid one, so FORGE would report a finding from a
PHP file that ``php -l`` rejects outright. ``syntax_error`` therefore only ever
meant *Python*, while a reader would reasonably take a clean bucket to cover
the whole repository.

This module closes that asymmetry using each language's own parser, and three
constraints keep it honest.

**Parse-only, never execution.** ``ruby -c``, ``php -l`` and ``node --check``
parse and exit. FORGE audits repositories it does not trust; running their code
to check a syntax claim would trade a reporting gap for a far worse one.

**Opt-in, never auto-detected.** Deciding by what is installed would make the
same repository audit differently on two machines, and the seal is supposed to
be reproducible bit-for-bit. The choice is part of the run configuration and is
recorded in coverage.

**Absence is a boundary, not a pass.** A declared validator that is not
installed yields ``validator_unavailable``. FORGE never converts "could not
check" into "checked and fine".
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from forge.languages.spec import LanguagePack

#: Generous enough for a large file, short enough that a hung tool cannot stall
#: an audit. A timeout is reported as its own state, never as valid syntax.
SYNTAX_TIMEOUT_SECONDS = 20

VALID = "syntax_valid"
INVALID = "syntax_error"
UNAVAILABLE = "validator_unavailable"
NOT_DECLARED = "no_validator_declared"
TIMEOUT = "validator_timed_out"
FAILED = "validator_failed"


def validator_status(pack: LanguagePack, suffix: str) -> str | None:
    """Return why an extension cannot be validated, or ``None`` when it can."""
    command = pack.syntax_commands.get(suffix.lower())
    if not command:
        return NOT_DECLARED
    if shutil.which(command[0]) is None:
        return UNAVAILABLE
    return None


def validate_syntax(path: str | Path, pack: LanguagePack) -> str:
    """Return one of the module's status constants for a single file.

    The command is invoked with an explicit argument list, never a shell, so a
    repository path cannot become part of a command line. Its output is
    discarded: the exit status is the whole answer, and keeping the tool's
    stderr out of the audit avoids importing text FORGE has not vetted into
    its own evidence.
    """
    suffix = Path(path).suffix.lower()
    unavailable = validator_status(pack, suffix)
    if unavailable is not None:
        return unavailable
    try:
        completed = subprocess.run(
            [*pack.syntax_commands[suffix], str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=SYNTAX_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return TIMEOUT
    except (OSError, subprocess.SubprocessError):
        return FAILED
    return VALID if completed.returncode == 0 else INVALID


def declared_validators() -> dict[str, tuple[str, ...]]:
    """Every declared parse-only command, keyed by extension.

    Reported with the run so a reader can see which extensions were actually
    verifiable and which were only ever going to be unverified.
    """
    from forge.languages import PACKS

    return {
        extension: command
        for pack in PACKS
        for extension, command in sorted(pack.syntax_commands.items())
    }


__all__ = (
    "FAILED", "INVALID", "NOT_DECLARED", "SYNTAX_TIMEOUT_SECONDS", "TIMEOUT",
    "UNAVAILABLE", "VALID", "declared_validators", "validate_syntax",
    "validator_status",
)
