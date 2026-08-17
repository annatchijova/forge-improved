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
from forge.languages.cpp import PACK as CPP
from forge.languages.csharp import PACK as CSHARP
from forge.languages.go import PACK as GO
from forge.languages.java import PACK as JAVA
from forge.languages.javascript import PACK as JS
from forge.languages.php import PACK as PHP
from forge.languages.ruby import PACK as RUBY
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
    assert analysis_depth(".java") == "lexical"
    assert analysis_depth(".cs") == "lexical"
    assert analysis_depth(".kt") == "none"
    assert analysis_depth(".md") == "none"


def test_recognized_languages_is_a_superset_of_what_is_analyzed():
    # Every analysable extension must also be a recognised language, otherwise
    # coverage would file a supported file under "not source at all".
    assert ANALYZED_EXTENSIONS <= set(RECOGNIZED_LANGUAGES)
    assert language_name(".go") == "Go"
    assert language_name(".kt") is None


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


# --------------------------------------------------------------------------
# False positives found by auditing the packs against idiomatic benign code
# --------------------------------------------------------------------------

def test_sprintf_in_a_bound_parameter_is_not_sql_injection():
    # `db.QueryRow("SELECT ... $1", fmt.Sprintf("%s", raw))` is the *safe* form:
    # the query is constant and the constructed value is a bound parameter.
    # Scanning the whole call instead of argument zero reported it as injection.
    source = 'err := db.QueryRow("SELECT count(*) FROM e WHERE ts > $1", fmt.Sprintf("%s", since)).Scan(&n)\n'
    assert not families(GO, source)
    assert families(GO, 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE n = %s", name))\n') == {
        ("sql-injection", 1)
    }


def test_a_generic_execute_call_is_not_a_query():
    # `execute` and `query` are not reserved for databases. Requiring the first
    # argument to actually contain SQL keeps ordinary domain code out.
    assert not families(RUST, 'step.execute(format!("step-{}", step.id))?;\n')
    assert families(RUST, 'sqlx::query(&format!("SELECT * FROM t WHERE n = {}", name));\n') == {
        ("sql-injection", 1)
    }


def test_parsing_a_string_literal_is_not_a_parser_boundary():
    # A compile-time constant cannot fail to parse at runtime, so unwrapping it
    # is not a boundary a reviewer can act on -- and idiomatic Rust is full of it.
    assert not families(RUST, 'let port: u16 = "8080".parse().unwrap();\n')
    assert families(RUST, 'let port: u16 = raw_header.parse().unwrap();\n') == {
        ("parser-boundary", 1)
    }


def test_parsing_a_locally_bound_literal_is_not_a_parser_boundary():
    source = 'let raw = "3";\nlet n = raw.parse::<u32>().expect("literal is valid");\n'
    assert not families(RUST, source)
    # The same shape with a value that did not come from a literal still counts.
    runtime_source = 'let raw = read_header();\nlet n = raw.parse::<u32>().expect("bad");\n'
    assert families(RUST, runtime_source) == {("parser-boundary", 2)}


def test_string_concatenated_sql_is_still_reported():
    # Narrowing to argument zero must not lose the non-Sprintf construction form.
    assert families(GO, 'db.Exec("DELETE FROM t WHERE n = " + name)\n') == {("sql-injection", 1)}


def test_benign_idiomatic_go_service_is_clean_except_declared_boundaries():
    source = (
        'const configName = "config.json"\n'
        'func LoadConfig(root string) (*Config, error) {\n'
        '\tdata, err := os.ReadFile(filepath.Join(root, configName))\n'
        '\tif err != nil { return nil, err }\n'
        '\tvar cfg Config\n'
        '\tif err := json.Unmarshal(data, &cfg); err != nil { return nil, err }\n'
        '\treturn &cfg, nil\n'
        '}\n'
        'func Render(tmpl *Template, target string) error {\n'
        '\treturn tmpl.Execute(os.Stdout, target)\n'
        '}\n'
    )
    # filepath.Join with a constant, a checked Unmarshal, and `tmpl.Execute`
    # (which is not `Exec(`) must all stay silent.
    assert not families(GO, source)


# --------------------------------------------------------------------------
# Java pack
# --------------------------------------------------------------------------

def test_java_reports_its_declared_families():
    source = (
        'import javax.script.ScriptEngineManager;\n'
        'public class Bad {\n'
        '  static final String apiKey = "sk-live-77";\n'
        '  void h(String userInput, Statement st, ScriptEngine e) throws Exception {\n'
        '    Files.readString(Paths.get(userInput));\n'
        '    st.executeQuery("SELECT * FROM t WHERE n = \'" + userInput + "\'");\n'
        '    Runtime.getRuntime().exec(userInput);\n'
        '    new ObjectInputStream(in).readObject();\n'
        '    e.eval(userInput);\n'
        '    DocumentBuilderFactory.newInstance();\n'
        '  }\n'
        '}\n'
    )
    assert families(JAVA, source) == {
        ("hardcoded-credential", 3),
        ("path-traversal", 5),
        ("sql-injection", 6),
        ("subprocess", 7),
        ("unsafe-deserialization", 8),
        ("dynamic-evaluation", 9),
        ("parser-boundary", 10),
    }


def test_java_deserialization_reports_once_per_read():
    # `new ObjectInputStream(in).readObject()` matched a construction pattern
    # and a read pattern, so one boundary produced two findings on one line at
    # different columns -- which the runtime's deduplication cannot collapse.
    findings = scan_source(JAVA, "s.java", "new ObjectInputStream(in).readObject();\n")
    assert [item.family for item in findings] == ["unsafe-deserialization"]


def test_java_benign_service_is_clean():
    source = (
        'public class UserService {\n'
        '    private static final String CONFIG = "application.yml";\n'
        '    public String loadConfig(Path root) throws Exception {\n'
        '        Path target = root.resolve(CONFIG).normalize();\n'
        '        return Files.readString(target);\n'
        '    }\n'
        '    public String findUser(Connection conn, long id) throws SQLException {\n'
        '        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");\n'
        '        ps.setLong(1, id);\n'
        '        return ps.executeQuery().getString(1);\n'
        '    }\n'
        '    public String describe(String name) { return "user " + name + " loaded"; }\n'
        '}\n'
    )
    assert not families(JAVA, source)


def test_java_xml_hardening_anywhere_in_the_file_clears_the_factory():
    # Hardening is conventionally applied a few lines below the factory, so the
    # check is file-scoped. A line-scoped one would report every correct usage.
    unhardened = "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
    hardened = unhardened + 'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
    assert families(JAVA, unhardened) == {("parser-boundary", 1)}
    assert not families(JAVA, hardened)


def test_java_eval_is_only_a_boundary_where_a_script_engine_is_imported():
    # Every other `eval` in a Java file is someone's ordinary method.
    assert not families(JAVA, "int total = calculator.eval(expression);\n")
    with_engine = "import javax.script.ScriptEngineManager;\nengine.eval(userInput);\n"
    assert families(JAVA, with_engine) == {("dynamic-evaluation", 2)}


def test_java_text_block_does_not_leak_its_contents_as_code():
    source = 'String doc = """\nRuntime.getRuntime().exec(evil)\n""";\nnew ProcessBuilder(cmd);\n'
    assert families(JAVA, source) == {("subprocess", 4)}


# --------------------------------------------------------------------------
# C# pack
# --------------------------------------------------------------------------

def test_csharp_reports_its_declared_families():
    source = (
        'class Bad {\n'
        '  const string ApiKey = "sk-live-88";\n'
        '  void H(string userInput, SqlConnection c) {\n'
        '    var body = File.ReadAllText(userInput);\n'
        '    var cmd = new SqlCommand($"SELECT * FROM t WHERE n = {userInput}", c);\n'
        '    Process.Start(userInput);\n'
        '    var f = new BinaryFormatter();\n'
        '    var o = f.Deserialize(stream);\n'
        '  }\n'
        '}\n'
    )
    assert families(CSHARP, source) == {
        ("hardcoded-credential", 2),
        ("path-traversal", 4),
        ("sql-injection", 5),
        ("subprocess", 6),
        ("unsafe-deserialization", 8),
    }


def test_csharp_verbatim_string_keeps_backslashes_from_becoming_escapes():
    # `@"C:\reports\"` ends at its own quote; treating the backslash as an
    # escape would swallow the terminator and blank the rest of the file.
    source = 'var banner = @"C:\\reports\\daily";\nProcess.Start(userInput);\n'
    assert families(CSHARP, source) == {("subprocess", 2)}


def test_csharp_doubled_quote_inside_a_verbatim_string_is_not_a_terminator():
    source = 'var q = @"say ""Process.Start(evil)"" now";\nProcess.Start(userInput);\n'
    assert families(CSHARP, source) == {("subprocess", 2)}


def test_csharp_interpolation_survives_masking_but_literal_text_does_not():
    from forge.languages import mask_source

    masked = mask_source('var s = $"prefix {userInput} suffix";\n', CSHARP)
    assert "{userInput}" in masked[0]
    assert "prefix" not in masked[0]


def test_csharp_safe_json_deserialize_is_not_native_deserialization():
    # `Deserialize` is how every safe JSON library spells its entry point, so
    # the file must name a formatter that rebuilds arbitrary object graphs.
    assert not families(CSHARP, "var c = JsonSerializer.Deserialize<Config>(body);\n")
    unsafe = "var f = new BinaryFormatter();\nvar o = f.Deserialize(stream);\n"
    assert families(CSHARP, unsafe) == {("unsafe-deserialization", 2)}


def test_csharp_benign_repository_is_clean():
    source = (
        'class OrderRepository {\n'
        '    private const string ConfigName = "appsettings.json";\n'
        '    public Config LoadConfig(string root) {\n'
        '        var target = Path.Combine(root, ConfigName);\n'
        '        var body = File.ReadAllText(target);\n'
        '        return JsonSerializer.Deserialize<Config>(body);\n'
        '    }\n'
        '    public string FindOrder(SqlConnection conn, int id) {\n'
        '        var cmd = new SqlCommand("SELECT code FROM orders WHERE id = @id", conn);\n'
        '        cmd.Parameters.AddWithValue("@id", id);\n'
        '        return (string)cmd.ExecuteScalar();\n'
        '    }\n'
        '}\n'
    )
    assert not families(CSHARP, source)


def test_a_name_is_not_tainted_merely_by_being_called_target():
    # `target = Path.Combine(root, ConfigName)` carries nothing external, while
    # the same shape fed from a parameter does. Judging by the name alone made
    # every conventional destination-path variable a traversal candidate.
    benign = 'var target = Path.Combine(root, ConfigName);\nvar body = File.ReadAllText(target);\n'
    assert not families(CSHARP, benign)
    tainted = 'var target = Path.Combine(userInput, ConfigName);\nvar body = File.ReadAllText(target);\n'
    assert families(CSHARP, tainted) == {("path-traversal", 2)}


# --------------------------------------------------------------------------
# Ruby pack
# --------------------------------------------------------------------------

def test_ruby_reports_its_declared_families():
    source = (
        'class Bad\n'
        '  API_TOKEN = "sk-live-99"\n'
        '  def run(params)\n'
        '    eval(params[:code])\n'
        '    system("echo #{params[:msg]}")\n'
        '    File.read(params[:path])\n'
        '    Marshal.load(params[:blob])\n'
        '  end\n'
        'end\n'
    )
    assert families(RUBY, source) == {
        ("hardcoded-credential", 2),
        ("dynamic-evaluation", 4),
        ("subprocess", 5),
        ("path-traversal", 6),
        ("unsafe-deserialization", 7),
    }


def test_ruby_begin_end_block_comment_is_not_code():
    # `=begin`/`=end` is line-anchored, so the masker has to be standing on the
    # newline that precedes it. Skipping newlines early made every such block
    # invisible and its prose was scanned as code.
    source = (
        "x = 1\n"
        "=begin\n"
        'this used to call system("rake db:migrate") and File.read(params[:p])\n'
        "=end\n"
        "y = 2\n"
    )
    assert not families(RUBY, source)


def test_ruby_begin_block_at_the_very_start_of_a_file_is_still_a_comment():
    # A licence header at offset zero has no preceding newline.
    source = "=begin\neval(payload)\n=end\nx = 1\n"
    assert not families(RUBY, source)


def test_ruby_heredoc_body_is_data_not_code():
    source = (
        "sql = <<~SQL\n"
        "  SELECT count(*) FROM orders WHERE eval(x) system(y)\n"
        "SQL\n"
        "eval(payload)\n"
    )
    assert families(RUBY, source) == {("dynamic-evaluation", 4)}


def test_ruby_backticks_execute_rather_than_quote():
    assert families(RUBY, "output = `ls -la #{dir}`\n") == {("subprocess", 1)}


def test_ruby_symbol_and_character_literal_do_not_open_a_string():
    source = "status = :pending\nletter = ?A\neval(payload)\n"
    assert families(RUBY, source) == {("dynamic-evaluation", 3)}


def test_ruby_safe_yaml_load_is_not_unsafe_deserialization():
    assert not families(RUBY, "config = YAML.safe_load(body)\n")
    assert families(RUBY, "config = YAML.load(body)\n") == {("unsafe-deserialization", 1)}


def test_ruby_orm_fragment_needs_no_select_keyword_but_still_needs_construction():
    # `.where` receives a clause, never a whole statement, so demanding SELECT
    # would lose the real injection while protecting nothing.
    assert families(RUBY, 'Order.where("name = \'#{params[:n]}\'")\n') == {("sql-injection", 1)}
    assert not families(RUBY, "Order.where('status = ?', params[:status])\n")
    assert not families(RUBY, "Order.where(status: params[:status])\n")


def test_ruby_benign_controller_is_clean():
    source = (
        "class OrdersController < ApplicationController\n"
        "  CONFIG_NAME = 'config/orders.yml'\n"
        "  def index\n"
        "    @orders = Order.where('status = ?', params[:status])\n"
        "  end\n"
        "  def config\n"
        "    YAML.safe_load(File.read(File.expand_path(CONFIG_NAME, Rails.root)))\n"
        "  end\n"
        "end\n"
    )
    assert not families(RUBY, source)


# --------------------------------------------------------------------------
# PHP pack
# --------------------------------------------------------------------------

def test_php_reports_its_declared_families():
    source = (
        '<?php\n'
        '$apiKey = "sk-live-11";\n'
        'function h($pdo, $page) {\n'
        '  eval($_GET["code"]);\n'
        '  system("echo " . $_GET["msg"]);\n'
        '  file_get_contents($_GET["path"]);\n'
        '  $pdo->query("SELECT * FROM t WHERE n = \'$_GET[name]\'");\n'
        '  unserialize($_POST["blob"]);\n'
        '  include $page;\n'
        '}\n'
    )
    assert families(PHP, source) == {
        ("hardcoded-credential", 2),
        ("dynamic-evaluation", 4),
        ("subprocess", 5),
        ("path-traversal", 6),
        ("sql-injection", 7),
        ("unsafe-deserialization", 8),
        ("dynamic-evaluation", 9),
    }


def test_php_markup_outside_the_code_delimiters_is_never_scanned():
    # A template is HTML until `<?php` opens. Prose in the markup must not be
    # read as code, however sink-shaped it looks.
    source = (
        '<h1>Orders</h1>\n'
        '<p>Run system("rm -rf /") is only prose here.</p>\n'
        '<?php\n'
        'eval($payload);\n'
        '?>\n'
        '<footer>eval($more)</footer>\n'
    )
    assert families(PHP, source) == {("dynamic-evaluation", 4)}


def test_php_nowdoc_body_is_inert():
    source = (
        '<?php\n'
        "$text = <<<'TEXT'\n"
        'eval($payload); and system($cmd); are inert here\n'
        'TEXT;\n'
        'unserialize($blob);\n'
    )
    assert families(PHP, source) == {("unsafe-deserialization", 5)}


def test_php_variable_interpolation_survives_masking_but_literal_text_does_not():
    from forge.languages import mask_source

    masked = mask_source('<?php\n$q = "SELECT * FROM t WHERE n = $name";\n', PHP)
    assert "$name" in masked[1]
    assert "SELECT" not in masked[1]


def test_php_literal_include_is_ordinary_composition():
    # `include $page` resolves at runtime and then executes; a literal one does not.
    assert not families(PHP, "<?php\nrequire_once __DIR__ . '/bootstrap.php';\n")
    assert families(PHP, "<?php\ninclude $page;\n") == {("dynamic-evaluation", 2)}


def test_php_prepared_statement_is_not_sql_injection():
    safe = (
        '<?php\n'
        "$stmt = $pdo->prepare('SELECT code FROM orders WHERE id = :id');\n"
        "$stmt->execute([':id' => $id]);\n"
    )
    assert not families(PHP, safe)


def test_php_realpath_clears_a_filesystem_path():
    assert not families(PHP, '<?php\n$target = realpath($root . "/cfg.ini");\nfile_get_contents($target);\n')
    assert families(PHP, '<?php\nfile_get_contents($_GET["path"]);\n') == {("path-traversal", 2)}


def test_every_analysable_extension_is_also_triageable():
    # A file triage never classifies can never become CONNECTED_ALIVE, so no
    # detector reaches it: invisible rather than declared out of scope, which
    # is the one outcome the coverage contract exists to prevent. This is how
    # `.tsx`, then `.php`, then `.rake` each shipped with a pack that could
    # read them and a triage that never handed them over.
    from forge.detector.stack import LANG_EXT

    assert ANALYZED_EXTENSIONS <= set(LANG_EXT), sorted(ANALYZED_EXTENSIONS - set(LANG_EXT))


def test_declared_families_cover_every_pack_the_lexical_auditor_owns():
    from forge.agents.lexical_auditor import DECLARED_FAMILIES
    from forge.languages import LEXICAL_AUDITOR_PACKS

    assert set(DECLARED_FAMILIES) == {pack.name for pack in LEXICAL_AUDITOR_PACKS}
    assert all(DECLARED_FAMILIES[name] for name in DECLARED_FAMILIES)


# --------------------------------------------------------------------------
# C / C++ pack
# --------------------------------------------------------------------------

def test_c_reports_its_declared_families():
    source = (
        '#include <stdio.h>\n'
        'static const char *api_key = "sk-live-42";\n'
        'void handle(char *user_input, char *dst) {\n'
        '    strcpy(dst, user_input);\n'
        '    sprintf(cmd, "echo %s", user_input);\n'
        '    system(cmd);\n'
        '    FILE *f = fopen(user_input, "r");\n'
        '    void *lib = dlopen(user_input, RTLD_NOW);\n'
        '}\n'
    )
    assert families(CPP, source) == {
        ("hardcoded-credential", 2),
        ("unbounded-copy", 4),
        ("unbounded-copy", 5),
        ("command-injection", 6),
        ("subprocess", 6),
        ("path-traversal", 7),
        ("dynamic-evaluation", 8),
    }


def test_c_benign_service_is_clean_except_the_declared_subprocess():
    source = (
        '/* Legacy note: this used to call system(cmd) and strcpy(dst, argv[1]). */\n'
        'static const char *CONFIG_NAME = "server.conf";\n'
        'int load_config(const char *root, char *out, size_t n) {\n'
        '    char resolved[PATH_MAX];\n'
        '    if (realpath(root, resolved) == NULL) { return -1; }\n'
        '    snprintf(out, n, "%s/%s", resolved, CONFIG_NAME);\n'
        '    FILE *fp = fopen(out, "r");\n'
        '    return fp == NULL ? -1 : 0;\n'
        '}\n'
        'int run_backup(void) { return system("/usr/local/bin/backup --quiet"); }\n'
    )
    # A literal command is a declared subprocess boundary and nothing more.
    assert families(CPP, source) == {("subprocess", 10)}


def test_c_bounded_copy_is_not_an_unbounded_one():
    assert not families(CPP, "snprintf(dst, n, \"%s\", src);\nstrncpy(dst, src, n);\n")
    assert families(CPP, "strcpy(dst, src);\n") == {("unbounded-copy", 1)}


def test_cpp_raw_string_uses_its_own_delimiter_to_close():
    # C++ closes with `)tag"`, not Rust's `"##`, so the shape is declared.
    source = 'const char *s = R"tag(strcpy(a, b); system(cmd);)tag";\nstrcpy(dst, src);\n'
    assert families(CPP, source) == {("unbounded-copy", 2)}


def test_c_character_literal_holding_a_quote_does_not_open_a_string():
    source = "char q = '\\\"';\nstrcpy(dst, src);\n"
    assert families(CPP, source) == {("unbounded-copy", 2)}


def test_c_query_is_found_when_the_driver_takes_the_handle_first():
    # `mysql_query(conn, query)` puts the query second. Fixing on argument zero
    # missed it entirely while reporting a constructed bound parameter
    # elsewhere as an injection.
    source = 'mysql_query(conn, sprintf(q, "SELECT * FROM t WHERE n = %s", user_input));\n'
    assert ("sql-injection", 1) in families(CPP, source)


def test_php_query_is_found_when_the_driver_takes_the_handle_first():
    source = '<?php\nmysqli_query($link, "SELECT * FROM t WHERE n = $id");\n'
    assert ("sql-injection", 2) in families(PHP, source)


def test_a_constructed_bound_parameter_is_still_not_an_injection():
    # The per-argument rule must not reintroduce the false positive that the
    # argument-zero restriction was added to remove.
    source = 'err := db.QueryRow("SELECT count(*) FROM e WHERE ts > $1", fmt.Sprintf("%s", since)).Scan(&n)\n'
    assert not families(GO, source)
