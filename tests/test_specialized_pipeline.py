import json
from fractions import Fraction

from forge.orchestrator import run_specialized_pipeline
from forge.disposition import determine_disposition

def put(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

def test_specialized_pipeline_merges_seals_and_attributes_all_agents(tmp_path):
    put(tmp_path, "main.py", "import bad\nimport security\nimport integrity\n")
    put(tmp_path, "bad.py", "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd)\n")
    put(tmp_path, "security.py", "password = 'real-secret'\nimport pickle\npickle.loads(raw)\n")
    put(tmp_path, "integrity.py", "import json\ndef score(decision):\n    value = float(decision)\n    json.dump({'score': value}, out)\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    sealed = json.loads((tmp_path / "out/verification-manifest.sealed.json").read_text())
    agents = {entry["finding"]["agent"] for entry in sealed["chain"]}
    assert {"bug_investigator", "security_auditor", "integrity_inspector"} <= agents
    assert json.loads((tmp_path / "out/verification-manifest.sealed.json").read_text())
    report = (tmp_path / "out/forge-report.html").read_text()
    assert "Coverage" in report and "security_auditor" in report and "integrity_inspector" in report
    assert result["coverage"]["coverage_ratio"] == {"numerator": 1, "denominator": 1}
    assert (tmp_path / "out/skills-runtime.json").is_file()

def test_coverage_surfaces_policy_exclusions(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, ".venv/lib/hidden.py", "password = 'never-scanned'\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    coverage = result["coverage"]
    assert ".venv/lib/hidden.py" in coverage["skipped_reasons"]["excluded_by_policy"]
    assert coverage["files_skipped"] >= 1

def test_coverage_counts_syntax_errors(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, "broken.py", "def broken(:\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    coverage = result["coverage"]
    assert "broken.py" in coverage["skipped_reasons"]["syntax_error"]
    assert coverage["files_analyzed"] == 1
    assert Fraction(coverage["coverage_ratio"]["numerator"], coverage["coverage_ratio"]["denominator"]) == Fraction(1, 2)

def test_audit_disposition_abstains_on_unverified_source_boundary(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, "broken.py", "def broken(:\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())
    assert metrics["audit_disposition"]["status"] == "ABSTAIN_INSUFFICIENT_SCOPE"
    assert "UNVERIFIED_SOURCE_BOUNDARY" == metrics["audit_disposition"]["reason_code"]
    assert "ABSTAIN_INSUFFICIENT_SCOPE" in (tmp_path / "out/forge-report.html").read_text()

def test_disposition_can_complete_with_findings_without_abstaining():
    class Coverage:
        skipped_reasons = {}
    class Triage:
        modules = []
    class Governance:
        applicability = {}
    finding = object()
    result = determine_disposition(coverage=Coverage(), triage=Triage(), governance=Governance(), findings=[finding])
    assert result.status == "COMPLETE_WITH_FINDINGS"

def test_ast_structural_agents_use_red_team_auditing_epistemic_vocabulary(tmp_path):
    put(tmp_path, "main.py", "import security\nimport integrity\n")
    put(tmp_path, "security.py", "password = 'real-secret'\n")
    put(tmp_path, "integrity.py", "def score(decision):\n    value = float(decision)\n    return value\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    sealed = json.loads((tmp_path / "out/verification-manifest.sealed.json").read_text())
    valid_levels = {"CODE FACT", "PLAUSIBLE HYPOTHESIS", "CONFIRMED BY INDUCTION", "FALSIFIED"}
    ast_agent_findings = [
        entry["finding"] for entry in sealed["chain"]
        if entry["finding"]["agent"] in {"security_auditor", "integrity_inspector"}
    ]
    assert ast_agent_findings, "fixture must produce at least one AST-structural finding to exercise the assertion"
    for finding in ast_agent_findings:
        assert finding["epistemic_level"] in valid_levels, (
            f"{finding['agent']} used epistemic_level={finding['epistemic_level']!r}, "
            f"which is not in the red-team-auditing vocabulary {valid_levels} "
            "(it must not reuse the category field's own value, e.g. 'OBSERVED')"
        )
        assert finding["epistemic_level"] != finding["category"], (
            "epistemic_level must not conflate with the category field (OBSERVED/INFERRED/OPINION)"
        )

def test_report_does_not_inline_raw_examinations_dict_at_scale(tmp_path):
    module_names = [f"mod{i}" for i in range(15)]
    put(tmp_path, "main.py", "".join(f"import {name}\n" for name in module_names))
    for i, name in enumerate(module_names):
        put(tmp_path, f"{name}.py", f"x = {i}\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    assert result["connected_alive"] == 16, "fixture must actually produce 15+ CONNECTED_ALIVE modules to exercise the scale case"
    report = (tmp_path / "out/forge-report.html").read_text()
    # html.escape() turns a raw dict repr's quotes into &#x27; / &quot; rather than
    # removing the dict shape, so check for the escaped form too, not just the
    # literal Python repr.
    assert "{'examined_clean'" not in report and "&#x27;examined_clean&#x27;:" not in report
    assert "examinations': {" not in report and "&#x27;examinations&#x27;: {" not in report
    metrics_section = report[report.index('id="agent-metrics"'):report.index('</section>', report.index('id="agent-metrics"'))]
    assert "mod0.py" not in metrics_section, (
        "per-module paths must not be inlined into the agent-metrics section once "
        "the module count exceeds the summary threshold; other sections (e.g. clean "
        "modules) are allowed to list module paths"
    )
    assert "examined_clean" in metrics_section, "a human-readable summary count must still be present"

def test_bug_investigator_examinations_distinguish_no_hypothesis_from_discarded(tmp_path):
    put(tmp_path, "main.py", "import boring\nimport risky\nimport confirmed\n")
    put(tmp_path, "boring.py", "x = 1\n")  # no risk keyword: no hypothesis ever generated
    put(tmp_path, "risky.py", "def run():\n    return eval('1 + 1')\n")  # hypothesis generated, discarded (literal, benign)
    put(tmp_path, "confirmed.py", "def run(expr):\n    return eval(expr)\n")  # hypothesis generated, survives as a finding
    run_specialized_pipeline(tmp_path, tmp_path / "out")
    report = (tmp_path / "out/forge-report.html").read_text()
    metrics_section = report[report.index('id="agent-metrics"'):report.index('</section>', report.index('id="agent-metrics"'))]
    assert "no_hypothesis_generated" in metrics_section
    assert "hypothesis_discarded_benign" in metrics_section
    assert "examined_with_findings" in metrics_section
    # The old conflated label must not survive for bug_investigator once split.
    bug_investigator_block = metrics_section[metrics_section.index("bug_investigator"):]
    bug_investigator_block = bug_investigator_block[:bug_investigator_block.index("</li>") + 5]
    assert "examined_clean" not in bug_investigator_block

def test_coverage_accounting_never_loses_readable_non_python_files(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, "README.md", "# not python, but readable text\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    coverage = result["coverage"]
    accounted_for = coverage["files_analyzed"] + sum(len(v) for v in coverage["skipped_reasons"].values())
    assert coverage["files_discovered"] == accounted_for, (
        "every discovered file must land in exactly one bucket: analyzed or a skipped_reasons category"
    )
    assert "README.md" in coverage["skipped_reasons"].get("non_python_not_analyzed", ())
