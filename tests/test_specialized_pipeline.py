import json
from fractions import Fraction

from forge.orchestrator import run_specialized_pipeline
from forge.disposition import determine_disposition
from forge.contradictions import find_contradictions

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


def test_disposition_completes_with_explicit_declared_boundary():
    class Coverage:
        skipped_reasons = {"non_python_not_analyzed": ("native.rs",)}
    class Triage:
        modules = [type("Module", (), {"path": "legacy.py", "module_class": "DEAD_WEIGHT"})()]
    class Governance:
        applicability = {}
    result = determine_disposition(coverage=Coverage(), triage=Triage(), governance=Governance(), findings=[])
    assert result.status == "COMPLETE_WITHIN_DECLARED_SCOPE"
    assert result.reason_code == "DECLARED_SCOPE_BOUNDARY"

def test_unavailable_specialized_agent_degrades_to_abstain(monkeypatch, tmp_path):
    put(tmp_path, "main.py", "x = 1\n")

    def unavailable(_root):
        raise RuntimeError("synthetic agent outage")

    monkeypatch.setattr("forge.runtime.security_auditor.audit", unavailable)
    run_specialized_pipeline(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())
    assert metrics["audit_disposition"]["status"] == "ABSTAIN_DEGRADED"
    assert any("security_auditor unavailable" in item for item in metrics["honest_degradation"]["limitations"])

def test_contradictory_credential_explanations_force_abstention(tmp_path):
    from forge.models import Evidence, Finding
    finding = Finding("OBSERVED", "CODE FACT", "tests/config.py", "hardcoded credential", (Evidence("source", "tests/config.py:1", "token = 'x'"),), "credential assignment", "security_auditor")
    contradictions = find_contradictions([finding], [{"module_path": "tests/config.py", "reason": "placeholder used in tests"}])
    assert len(contradictions) == 1
    class Coverage:
        skipped_reasons = {}
    class Triage:
        modules = []
    class Governance:
        applicability = {}
    result = determine_disposition(coverage=Coverage(), triage=Triage(), governance=Governance(), findings=[finding], contradiction_reasons=[item.description for item in contradictions])
    assert result.status == "ABSTAIN_UNDETERMINED"
    assert result.reason_code == "CONTRADICTORY_EVIDENCE"

def test_undetermined_governance_applicability_alone_is_a_declared_boundary():
    class Coverage:
        skipped_reasons = {}
    class Triage:
        modules = []
    class Governance:
        applicability = {"main.py": {"validate-at-the-boundary": "UNDETERMINED"}}
    result = determine_disposition(coverage=Coverage(), triage=Triage(), governance=Governance(), findings=[])
    assert result.status == "COMPLETE_WITHIN_DECLARED_SCOPE"
    assert "skill_applicability: 1 undetermined result(s)" in result.evidence_boundary

def test_undetermined_governance_applicability_does_not_abstain_even_at_high_proportion():
    # No proportional gate: whether it is 1 undetermined result out of 1000
    # or 999 out of 1000, it is reported as a declared boundary either way,
    # never silently hidden and never a hard block on its own.
    class Coverage:
        skipped_reasons = {}
    class Triage:
        modules = []
    class Governance:
        applicability = {f"m{i}.py": {"validate-at-the-boundary": "UNDETERMINED"} for i in range(999)} | {"m999.py": {"validate-at-the-boundary": "APPLICABLE"}}
    result = determine_disposition(coverage=Coverage(), triage=Triage(), governance=Governance(), findings=[])
    assert result.status == "COMPLETE_WITHIN_DECLARED_SCOPE"
    assert "skill_applicability: 999 undetermined result(s)" in result.evidence_boundary

def test_audit_seals_repository_snapshot_and_provenance(tmp_path):
    put(tmp_path, "main.py", "def run(value):\n    return eval(value)\n")
    run_specialized_pipeline(tmp_path, tmp_path / "out")
    sealed = json.loads((tmp_path / "out/verification-manifest.sealed.json").read_text())
    assert len(sealed["manifest"]["repository_snapshot_sha256"]) == 64
    finding = sealed["chain"][0]["finding"]
    assert "AST" in finding["provenance"]
    assert "REPRODUCED" in finding["provenance"]

def test_unsupported_source_language_and_undetermined_governance_are_a_declared_boundary_not_abstain(tmp_path):
    # An unsupported source language (native.rs) and an UNDETERMINED skill
    # applicability result (main.py: no clear input-boundary signal for
    # validate-at-the-boundary) are declared boundaries of the same kind as
    # an excluded module, not failures - the specialized agents still ran
    # fully. A single ambiguous applicability result out of the whole
    # repository previously forced a hard ABSTAIN_UNDETERMINED regardless of
    # how small a fraction it was (found via a real audit that abstained on
    # a two-file repository for exactly this reason). Both boundaries must
    # still be visible in evidence_boundary - reported, never hidden - they
    # just no longer block a completeness claim on their own.
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, "native.rs", "fn main() {}\n")
    result = run_specialized_pipeline(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())
    assert metrics["audit_disposition"]["status"] == "COMPLETE_WITHIN_DECLARED_SCOPE"
    assert "unsupported_source_language: Rust (1 file(s))" in metrics["audit_disposition"]["evidence_boundary"]
    assert "skill_applicability: 1 undetermined result(s)" in metrics["audit_disposition"]["evidence_boundary"]

def test_self_assessment_is_bounded_not_a_quality_score(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    run_specialized_pipeline(tmp_path, tmp_path / "out")
    metrics = json.loads((tmp_path / "out/metrics.json").read_text())
    assessment = metrics["self_assessment"]
    assert assessment["specialized_agents"] == {"available": 5, "total": 5}
    # A single file with an UNDETERMINED governance-applicability result no
    # longer forces ABSTAIN (see disposition.py) - main.py alone completes,
    # so the boundary here is the finding evidence itself, not the scope.
    assert assessment["confidence_boundary"] == "evidence-bounded"
    assert "quality score" in assessment["note"]

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
    assert coverage["language_coverage"]["Python"] == {"analyzed": 1, "abstained": 0}
    assert coverage["language_coverage"]["MD"] == {"analyzed": 0, "abstained": 1}


def test_coverage_makes_js_ts_and_unsupported_language_scope_explicit(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    put(tmp_path, "frontend.ts", "export const parse = (raw) => JSON.parse(raw);\n")
    put(tmp_path, "native.rs", "fn main() {}\n")
    coverage = run_specialized_pipeline(tmp_path, tmp_path / "out")["coverage"]
    assert coverage["language_coverage"]["JavaScript/TypeScript"] == {"analyzed": 0, "abstained": 1}
    assert coverage["language_coverage"]["RS"] == {"analyzed": 0, "abstained": 1}
    assert "native.rs" in coverage["skipped_reasons"]["non_python_not_analyzed"]
