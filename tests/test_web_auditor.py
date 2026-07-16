from forge.agents.web_auditor import audit


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_web_auditor_analyzes_js_and_ts_and_reports_high_signal_patterns(tmp_path):
    write(tmp_path, "main.ts", "export function parse(raw: string) { return JSON.parse(raw); }\n")
    write(tmp_path, "worker.js", "const run = (cmd) => child_process.exec(cmd);\n")
    result, analyzed = audit(tmp_path)
    assert set(analyzed) == {"main.ts", "worker.js"}
    assert {(item.path, item.family) for item in result.findings} == {
        ("main.ts", "parser-boundary"),
        ("worker.js", "subprocess"),
    }


def test_web_auditor_does_not_flag_json_parse_with_visible_boundary(tmp_path):
    write(tmp_path, "safe.ts", """
try {
  const data = JSON.parse(raw);
} catch (error) {
  return fallback(error);
}
""")
    result, analyzed = audit(tmp_path)
    assert analyzed == ("safe.ts",)
    assert not result.findings


def test_web_auditor_handles_comments_as_non_executable_text(tmp_path):
    write(tmp_path, "notes.ts", "// eval(userInput)\nconst label = 'JSON.parse(raw)';\n")
    result, _ = audit(tmp_path)
    assert not result.findings
