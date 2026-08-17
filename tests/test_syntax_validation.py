"""Tests for optional syntax verification of lexically scanned source.

Python source is parsed before it is analysed, so a file FORGE cannot parse
blocks the completeness claim. No lexical language had any equivalent: a
masked-text scan reads a malformed file exactly as happily as a valid one, so
``syntax_error`` only ever meant *Python* while a reader would take the empty
bucket to cover the repository.

The constraints matter as much as the capability, so they are tested too: the
tools must be parse-only, the feature must stay opt-in so one repository audits
identically on two machines, and an absent validator must report as unverified
rather than as a pass.
"""
from __future__ import annotations

import shutil

import pytest

from forge import Runtime
from forge.languages import pack_for_path
from forge.languages.javascript import PACK as JS
from forge.languages.php import PACK as PHP
from forge.languages.ruby import PACK as RUBY
from forge.languages.validation import (
    INVALID,
    NOT_DECLARED,
    UNAVAILABLE,
    VALID,
    declared_validators,
    validate_syntax,
    validator_status,
)

requires_php = pytest.mark.skipif(shutil.which("php") is None, reason="php not installed")
requires_ruby = pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby not installed")


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --------------------------------------------------------------------------
# The declared contract
# --------------------------------------------------------------------------

def test_every_declared_validator_is_a_parse_only_invocation():
    # FORGE audits repositories it does not trust. Running their code to settle
    # a syntax question would trade a reporting gap for a far worse one.
    parse_only = {("ruby", "-c"), ("php", "-l"), ("node", "--check")}
    for extension, command in declared_validators().items():
        assert tuple(command) in parse_only, f"{extension} declares {command}"


def test_validators_are_declared_per_extension_not_per_pack():
    # `node --check` rejects `.jsx` outright and accepts `.ts` only on newer
    # Node, so a pack-wide declaration would fabricate a blocking syntax error
    # on valid source and make the verdict depend on the toolchain version.
    assert ".js" in JS.syntax_commands
    assert ".jsx" not in JS.syntax_commands
    assert ".ts" not in JS.syntax_commands
    assert validator_status(JS, ".jsx") == NOT_DECLARED


def test_an_undeclared_extension_is_unverified_never_valid():
    assert validate_syntax("component.jsx", JS) == NOT_DECLARED


def test_a_missing_validator_reports_unavailable_rather_than_passing(monkeypatch):
    monkeypatch.setattr("forge.languages.validation.shutil.which", lambda _name: None)
    assert validator_status(PHP, ".php") == UNAVAILABLE
    assert validate_syntax("anything.php", PHP) == UNAVAILABLE


# --------------------------------------------------------------------------
# Real parsers
# --------------------------------------------------------------------------

@requires_php
def test_php_parser_separates_valid_from_malformed(tmp_path):
    good = write(tmp_path, "good.php", "<?php\nfunction h() { return 1; }\n")
    bad = write(tmp_path, "bad.php", "<?php\nfunction h( {\n  system($_GET['c']);\n")
    assert validate_syntax(good, PHP) == VALID
    assert validate_syntax(bad, PHP) == INVALID


@requires_ruby
def test_ruby_parser_separates_valid_from_malformed(tmp_path):
    good = write(tmp_path, "good.rb", "class Good\n  def run; 1; end\nend\n")
    bad = write(tmp_path, "bad.rb", "class Bad\n  def run(\n    eval(x)\n")
    assert validate_syntax(good, RUBY) == VALID
    assert validate_syntax(bad, RUBY) == INVALID


def test_the_pack_that_owns_a_file_is_the_one_consulted():
    assert pack_for_path("app/models/order.rb") is RUBY
    assert pack_for_path("public/index.php") is PHP


# --------------------------------------------------------------------------
# Runtime integration
# --------------------------------------------------------------------------

def test_verification_is_off_by_default_and_says_so(tmp_path):
    # Off is the stdlib-only path. The claim still has to be stated, or an
    # empty syntax_error bucket reads as "nothing was malformed" when nothing
    # in that language was ever examined.
    write(tmp_path, "main.py", "x = 1\n")
    write(tmp_path, "index.php", "<?php\nunserialize($_POST['b']);\n")
    coverage = Runtime().audit(tmp_path, tmp_path / "out").coverage
    verification = coverage["syntax_verification"]
    assert verification["requested"] is False
    assert verification["python"] == "verified_by_ast_parse"
    assert verification["by_language"]["PHP"] == "not_requested"
    assert "index.php" not in coverage["skipped_reasons"].get("syntax_error", ())


@requires_php
def test_a_malformed_lexical_file_becomes_a_blocking_boundary_when_verified(tmp_path):
    # The defect this closes: FORGE reported a finding out of a PHP file that
    # `php -l` rejects, and the disposition never knew.
    write(tmp_path, "main.py", "x = 1\n")
    write(tmp_path, "index.php", "<?php\nfunction h( {\n  system($_GET['c']);\n")
    coverage = Runtime(syntax_validation=True).audit(tmp_path, tmp_path / "out").coverage
    assert "index.php" in coverage["skipped_reasons"]["syntax_error"]
    assert coverage["syntax_verification"]["by_language"]["PHP"] == "verified"


@requires_php
def test_valid_lexical_source_still_counts_as_analyzed_when_verified(tmp_path):
    write(tmp_path, "main.py", "x = 1\n")
    write(tmp_path, "index.php", "<?php\nunserialize($_POST['b']);\n")
    coverage = Runtime(syntax_validation=True).audit(tmp_path, tmp_path / "out").coverage
    assert not coverage["skipped_reasons"].get("syntax_error")
    assert coverage["files_analyzed"] == coverage["eligible_source_files"] == 2


@requires_php
def test_a_rejected_file_does_not_have_its_findings_suppressed(tmp_path):
    # FORGE never hides evidence. A malformed file may still hold a real defect
    # that survives the syntax being fixed, so the finding is kept and the
    # unverified source boundary is reported alongside it.
    write(tmp_path, "index.php", "<?php\nfunction h( {\n  system($_GET['c']);\n")
    result = Runtime(syntax_validation=True).audit(tmp_path, tmp_path / "out")
    assert result.findings >= 1
    assert "index.php" in result.coverage["skipped_reasons"]["syntax_error"]


def test_coverage_keeps_fields_added_after_its_hand_written_copy(tmp_path):
    # The runtime used to rebuild CoverageReport field by field late in the
    # audit, which silently dropped every field added to the model after that
    # copy was written -- syntax_verification arrived as an empty dict.
    write(tmp_path, "main.py", "def f(value):\n    return eval(value)\n")
    coverage = Runtime().audit(tmp_path, tmp_path / "out").coverage
    assert coverage["syntax_verification"], "a late rebuild dropped the field again"
    assert coverage["ast_verified_families"], "the late rebuild still has to attach these"
