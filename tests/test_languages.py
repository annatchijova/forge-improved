"""Tests for the language-pack registry, the masker, and the Go/Rust packs.

The masking tests carry most of the weight here. Every detector in every pack
matches against masked source, so a masking defect is not a local bug: it
either invents findings out of prose (a comment that mentions ``eval``) or
erases real ones (a phantom string that blanks the rest of a file). Each pack's
tests therefore pair a positive with the benign twin that must stay silent.
"""
from __future__ import annotations

import time

import pytest

from forge.agents.lexical_auditor import audit as lexical_audit
from forge.agents.web_auditor import audit as web_audit
from forge.languages import (
    ANALYZED_EXTENSIONS,
    PACKS,
    RECOGNIZED_LANGUAGES,
    analysis_depth,
    language_name,
    mask_source,
    pack_for_path,
    scan_source,
)
from forge.languages.go import PACK as GO
from forge.languages.javascript import PACK as JS
from forge.languages.rust import PACK as RUST


def families(pack, source):
    return {(item.family, item.line) for item in scan_source(pack, "sample", source)}


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

def test_no_two_packs_claim_the_same_extension():
    # The registry enforces this at import time; assert the invariant holds so
    # a future pack cannot silently steal another language's files.
    seen: dict[str, str] = {}
    for pack in PACKS:
        for extension in pack.extensions:
            assert extension not in seen, f"{extension} claimed twice"
            seen[extension] = pack.name


def test_analysis_depth_distinguishes_parsed_from_scanned_from_unanalyzed():
    assert analysis_depth(".py") == "ast"
    assert analysis_depth(".go") == "lexical"
    assert analysis_depth(".rs") == "lexical"
    assert analysis_depth(".tsx") == "lexical"
    assert analysis_depth(".java") == "none"
    assert analysis_depth(".md") == "none"


def test_recognized_languages_is_a_superset_of_what_is_analyzed():
    # Every analysable extension must also be a recognised language, otherwise
    # coverage would file a supported file under "not source at all".
    assert ANALYZED_EXTENSIONS <= set(RECOGNIZED_LANGUAGES)
    assert language_name(".go") == "Go"
    assert language_name(".java") is None


def test_pack_lookup_is_by_extension_and_case_insensitive():
    assert pack_for_path("src/main.RS") is RUST
    assert pack_for_path("cmd/app/main.go") is GO
    assert pack_for_path("Component.TSX") is JS
    assert pack_for_path("notes.md") is None


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

def test_masking_preserves_line_and_column_geometry():
    source = 'const a = "hidden";\n// comment\nconst b = 2;\n'
    masked = mask_source(source, JS)
    assert len(masked) == len(source.splitlines())
    for original, blanked in zip(source.splitlines(), masked):
        assert len(original) == len(blanked)


def test_masking_blanks_string_data_but_keeps_delimiters():
    masked = mask_source('const a = "eval(x)";\n', JS)
    assert "eval" not in masked[0]
    assert masked[0].count('"') == 2


def test_template_interpolation_survives_masking_because_it_is_code():
    # `${req.query.p}` is an expression reaching a sink, not inert text. The
    # literal text around it is still blanked.
    masked = mask_source("readFile(`/data/${req.query.p}.json`);\n", JS)
    assert "${req.query.p}" in masked[0]
    assert "/data/" not in masked[0]


def test_go_backtick_raw_string_spans_lines_without_leaking_code():
    source = 'x := `\nexec.Command(evil)\n`\nexec.Command(real)\n'
    assert families(GO, source) == {("subprocess", 4)}


def test_rust_nested_block_comment_closes_at_the_right_depth():
    source = "/* outer /* inner */ still comment */\nunsafe { f(); }\n"
    assert families(RUST, source) == {("unsafe-block", 2)}


def test_rust_raw_string_hash_fence_is_matched_by_its_own_width():
    source = 'let s = r##"unsafe { } "# not the end"##;\nunsafe { g(); }\n'
    assert families(RUST, source) == {("unsafe-block", 2)}


def test_rust_lifetime_does_not_open_a_phantom_string():
    # `&'a str` shares the apostrophe with a char literal. Reading it as a
    # string opener would blank every following line and silence the file.
    source = "fn f<'a>(x: &'a str) {}\nunsafe { h(); }\n"
    assert families(RUST, source) == {("unsafe-block", 2)}


def test_rust_char_literal_holding_a_quote_does_not_open_a_string():
    source = "let q = '\"';\nunsafe { h(); }\n"
    assert families(RUST, source) == {("unsafe-block", 2)}


def test_go_rune_literal_holding_a_quote_does_not_open_a_string():
    source = "q := '\"'\nexec.Command(name)\n"
    assert families(GO, source) == {("subprocess", 2)}


def test_javascript_regex_character_class_does_not_open_a_string():
    source = "const re = /['\"]/g;\neval(payload);\n"
    assert ("dynamic-evaluation", 2) in families(JS, source)


def test_unterminated_literal_is_masked_in_linear_time():
    # A minified bundle or a truncated template must be ordinary input, never a
    # denial-of-service vector for the audit itself.
    source = "const payload = `" + ("x" * 200_000) + "\n"
    started = time.monotonic()
    findings = scan_source(JS, "pathological.js", source)
    assert not findings
    assert time.monotonic() - started < 5.0


# --------------------------------------------------------------------------
# Go pack
# --------------------------------------------------------------------------

def test_go_reports_its_declared_families():
    source = (
        'package main\n'
        'const apiKey = "sk-live-1234"\n'
        'func h(userPath string, name string) {\n'
        '\tdata, _ := os.ReadFile(userPath)\n'
        '\t_ = json.Unmarshal(data, &v)\n'
        '\tdb.Query(fmt.Sprintf("SELECT %s", name))\n'
        '\texec.Command("sh", "-c", fmt.Sprintf("echo %s", name))\n'
        '}\n'
    )
    assert families(GO, source) == {
        ("hardcoded-credential", 2),
        ("path-traversal", 4),
        ("parser-boundary", 5),
        ("sql-injection", 6),
        ("command-injection", 7),
        ("subprocess", 7),
    }


def test_go_benign_twin_stays_silent():
    source = (
        'package main\n'
        '// exec.Command(userInput) and os.ReadFile(userPath) in a comment\n'
        'const apiKey = "changeme"\n'
        'func h(userPath string, name string) error {\n'
        '\tclean := filepath.Clean(userPath)\n'
        '\tdata, err := os.ReadFile(clean)\n'
        '\tif err != nil { return err }\n'
        '\tif err := json.Unmarshal(data, &v); err != nil { return err }\n'
        '\tdb.Query("SELECT * FROM t WHERE n = ?", name)\n'
        '\texec.Command("git", "status")\n'
        '\treturn nil\n'
        '}\n'
    )
    assert families(GO, source) == {("subprocess", 10)}


def test_go_checked_unmarshal_error_is_not_a_parser_boundary():
    assert not families(GO, "err := json.Unmarshal(data, &v)\n")
    assert families(GO, "_ = json.Unmarshal(data, &v)\n") == {("parser-boundary", 1)}


def test_go_direct_program_execution_is_not_command_injection():
    # No shell parses these arguments, so it is a subprocess boundary only.
    source = 'exec.Command("git", fmt.Sprintf("--since=%s", since))\n'
    assert families(GO, source) == {("subprocess", 1)}


# --------------------------------------------------------------------------
# Rust pack
# --------------------------------------------------------------------------

def test_rust_reports_its_declared_families():
    source = (
        'const API_TOKEN: &str = "tok_live_31ab";\n'
        'fn run(user_input: &str) {\n'
        '    let body = fs::read_to_string(user_input).unwrap();\n'
        '    let v: Value = serde_json::from_str(&body).unwrap();\n'
        '    Command::new("sh").arg("-c").arg(format!("echo {}", user_input));\n'
        '    unsafe { libc::abort(); }\n'
        '}\n'
    )
    assert families(RUST, source) == {
        ("hardcoded-credential", 1),
        ("path-traversal", 3),
        ("parser-boundary", 4),
        ("command-injection", 5),
        ("subprocess", 5),
        ("unsafe-block", 6),
    }


def test_rust_benign_twin_stays_silent():
    source = (
        '// unsafe { } and File::open(user_input) in a comment\n'
        'const API_TOKEN: &str = "placeholder";\n'
        'fn run(user_input: &str) -> Result<(), Error> {\n'
        '    let clean = Path::new(user_input).canonicalize()?;\n'
        '    let body = fs::read_to_string(clean)?;\n'
        '    let v: Value = serde_json::from_str(&body)?;\n'
        '    Ok(())\n'
        '}\n'
    )
    assert not families(RUST, source)


def test_rust_handled_parse_is_not_a_parser_boundary():
    assert not families(RUST, "let v = serde_json::from_str(&body)?;\n")
    assert families(RUST, "let v = serde_json::from_str(&body).expect(\"bad\");\n") == {
        ("parser-boundary", 1)
    }


# --------------------------------------------------------------------------
# JavaScript/TypeScript, deepened
# --------------------------------------------------------------------------

def test_destructured_child_process_import_is_recognized():
    source = 'const { execFile } = require("child_process");\nexecFile(cmd);\n'
    assert ("subprocess", 2) in families(JS, source)


def test_a_similarly_named_method_is_not_a_subprocess():
    # `db.exec(...)` must stay silent: the name alone is not the boundary, the
    # binding to child_process is.
    assert not families(JS, "const result = db.exec(statement);\n")


def test_interpolated_path_reaches_a_file_operation():
    source = "const read = (dir, req) => readFile(`${dir}/${req.query.p}`);\n"
    assert ("path-traversal", 1) in families(JS, source)


def test_parameter_bound_query_is_not_sql_injection():
    assert not families(JS, "db.query('SELECT * FROM t WHERE id = ?', [id]);\n")
    assert families(JS, "db.query(`SELECT * FROM t WHERE id = ${id}`);\n") == {
        ("sql-injection", 1)
    }


def test_placeholder_credential_is_not_reported():
    assert not families(JS, 'const apiKey = "changeme";\n')
    assert families(JS, 'const apiKey = "sk-live-abc123";\n') == {
        ("hardcoded-credential", 1)
    }


# --------------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------------

def test_lexical_auditor_covers_go_and_rust_and_leaves_web_to_web_auditor(tmp_path):
    write(tmp_path, "main.go", 'package main\nconst apiKey = "sk-live-1"\n')
    write(tmp_path, "lib.rs", 'const API_TOKEN: &str = "tok-2";\n')
    write(tmp_path, "app.ts", 'const apiKey = "sk-live-3";\n')
    result, analyzed = lexical_audit(tmp_path)
    assert set(analyzed) == {"main.go", "lib.rs"}
    assert result.examinations["app.ts"] == "excluded_by_scope"
    assert {item.language for item in result.findings} == {"Go", "Rust"}

    web_result, web_analyzed = web_audit(tmp_path)
    assert set(web_analyzed) == {"app.ts"}
    assert {item.language for item in web_result.findings} == {"JavaScript/TypeScript"}


def test_lexical_auditor_honours_the_triage_scope_it_is_given(tmp_path):
    write(tmp_path, "used.go", 'package main\nconst apiKey = "sk-live-1"\n')
    write(tmp_path, "orphan.go", 'package main\nconst apiKey = "sk-live-2"\n')
    result, analyzed = lexical_audit(tmp_path, eligible={"used.go"})
    assert analyzed == ("used.go",)
    assert result.examinations["orphan.go"] == "excluded_by_scope"


def test_lexical_findings_never_claim_exploitability(tmp_path):
    # No induction harness exists for Go or Rust, so nothing here may be raised
    # above an observation regardless of how strong the pattern looks.
    write(tmp_path, "main.go", 'package main\nfunc h(userPath string) {\n\tos.ReadFile(userPath)\n}\n')
    result, _ = lexical_audit(tmp_path)
    assert result.findings
    assert all(item.exploitability == "NOT_ASSESSED" for item in result.findings)


def test_lexical_scan_order_is_deterministic(tmp_path):
    # Finding order reaches the audit seal, so an identical tree must produce
    # an identical sequence on every run.
    write(tmp_path, "b.go", 'package main\nfunc h(userPath string) { os.ReadFile(userPath) }\n')
    write(tmp_path, "a.rs", 'fn h(user_input: &str) { fs::read(user_input); }\nunsafe { x(); }\n')
    def identity(result):
        return [(item.path, item.line, item.column, item.family) for item in result.findings]

    first, _ = lexical_audit(tmp_path)
    second, _ = lexical_audit(tmp_path)
    assert identity(first) == identity(second)
    assert len(identity(first)) > 1
    for path in {item.path for item in first.findings}:
        within_file = [item for item in identity(first) if item[0] == path]
        assert within_file == sorted(within_file)


@pytest.mark.parametrize("pack", PACKS, ids=[pack.name for pack in PACKS])
def test_every_pack_scans_empty_and_whitespace_source_without_error(pack):
    assert scan_source(pack, "empty", "") == []
    assert scan_source(pack, "blank", "\n\n   \n") == []


@pytest.mark.parametrize("pack", PACKS, ids=[pack.name for pack in PACKS])
def test_no_finding_text_collides_with_a_contradiction_marker(pack):
    # find_contradictions reads any co-located finding whose text contains one
    # of these words as an alternative explanation for a credential. A Go SQL
    # finding once said "instead of placeholder binding", which made every
    # module holding both findings abstain the whole audit for a reason nobody
    # had asserted. Finding text must stay clear of these words.
    reserved = ("placeholder", "fixture", "test value", "test-only", "example")
    descriptions = [rule.description for rule in pack.sinks]
    probe = (
        'const apiKey = "sk-live-1";\n'
        'db.query(`SELECT ${id}`);\n'
        'exec.Command("sh", "-c", fmt.Sprintf("%s", name))\n'
        'Command::new("sh").arg("-c").arg(format!("{}", user_input));\n'
        'fs::read_to_string(user_input).unwrap();\n'
        'os.ReadFile(userPath)\n'
        '_ = json.Unmarshal(data, &v)\n'
        'unsafe { x(); }\n'
        'readFile(`${req.query.p}`);\n'
    )
    descriptions += [item.description for item in scan_source(pack, "probe", probe)]
    for description in descriptions:
        lowered = description.lower()
        assert not [word for word in reserved if word in lowered], description
