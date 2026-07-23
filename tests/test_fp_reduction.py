from forge.agents.security_auditor import audit as security_audit
from forge.agents.web_auditor import audit as web_audit
from forge.agents.integrity_inspector import inspect as integrity_inspect
from forge.models import Evidence, Finding
from types import SimpleNamespace

from forge.runtime import _agent_finding, _deduplicate_findings, _with_severity
from forge.severity import is_test_module, severity_for


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_python_path_barriers_propagate_and_remain_line_sensitive(tmp_path):
    _write(tmp_path, "safe.py", """\
import os
def save(slug):
    filename = os.path.basename(slug)
    safe_name = filename
    return open(safe_name)
""")
    _write(tmp_path, "allowlisted.py", """\
ALLOWED = {"safe.txt"}
def load(name):
    if name not in ALLOWED:
        raise ValueError(name)
    return open(name)
""")
    _write(tmp_path, "unsafe.py", """\
def load(name):
    return open(name)
""")
    _write(tmp_path, "late.py", """\
import os
def load(name):
    result = open(name)
    name = os.path.basename(name)
    return result
""")
    findings = security_audit(tmp_path).findings
    assert [(item.path, item.line) for item in findings if item.family == "path-traversal"] == [
        ("late.py", 3), ("unsafe.py", 2),
    ]


def test_path_controllability_distinguishes_http_from_internal_constant_helper(tmp_path):
    _write(tmp_path, "routes.py", """\
@app.post("/upload")
def upload(path):
    return open(path)
""")
    _write(tmp_path, "internal.py", """\
from pathlib import Path
def _load(path):
    return open(path)
def analyze():
    return _load(Path(__file__))
""")
    by_path = {item.path: item for item in security_audit(tmp_path).findings if item.family == "path-traversal"}
    assert by_path["routes.py"].controllability == "ATTACKER_CONTROLLED"
    assert by_path["internal.py"].controllability == "INTERNAL_ONLY"
    assert severity_for("internal.py", "CODE FACT", "path reaches open()", family="path-traversal", controllability="INTERNAL_ONLY") == "MEDIUM"


def test_mixed_private_helper_callers_never_degrade_to_internal_only(tmp_path):
    _write(tmp_path, "mixed.py", """\
@app.post("/read")
def read(request):
    return _sink(request.args["path"])

def _sink(path):
    return open(path)

def startup():
    return _sink("config.json")
""")
    finding = next(item for item in security_audit(tmp_path).findings if item.family == "path-traversal")
    assert finding.controllability == "UNDETERMINED"


def test_web_path_sanitizer_names_propagate_to_sink(tmp_path):
    _write(tmp_path, "safe.ts", "const slug = path.basename(input);\nconst filename = slug;\nfs.writeFileSync(filename, data);\n")
    _write(tmp_path, "unsafe.ts", "fs.writeFileSync(input, data);\n")
    findings, _ = web_audit(tmp_path)
    assert [(item.path, item.family) for item in findings if item.family == "path-traversal"] == [("unsafe.ts", "path-traversal")]


def test_web_multiline_unresolved_path_is_explicit_observation(tmp_path):
    _write(tmp_path, "pending.ts", "fs.writeFileSync(\n  buildTarget(input),\n  body\n);\n")
    findings, _ = web_audit(tmp_path)
    path_findings = [item for item in findings if item.family == "path-traversal"]
    assert path_findings and "requires verification" in path_findings[0].description


def test_dedup_identity_collapses_variable_names_but_preserves_occurrences():
    first = Finding("OBSERVED", "CODE FACT", "app.py", "unversioned serialization", (Evidence("source", "app.py:7", "json.dumps(payload)"),), "first")
    second = Finding("OBSERVED", "CODE FACT", "app.py", "unversioned serialization", (Evidence("source", "app.py:7", "json.dumps(report)"),), "second")
    result = _deduplicate_findings([first, second])
    assert len(result) == 1
    assert result[0].occurrences == ("app.py:7", "app.py:7")


def test_dedup_keeps_distinct_path_sinks_on_the_same_line(tmp_path):
    _write(tmp_path, "main.py", "def load(a, b): open(a); open(b)\n")
    raw = [item for item in security_audit(tmp_path).findings if item.family == "path-traversal"]
    assert len(raw) == 2
    assert len({item.column for item in raw}) == 2
    findings = [_agent_finding("security_auditor", item) for item in raw]
    result = _deduplicate_findings(findings)
    assert len(result) == 2
    assert {item.evidence[0].source for item in result} == {
        item.evidence[0].source for item in findings
    }


def test_money_as_float_covers_literals_division_and_sql_dialects_without_decimal_fp(tmp_path):
    _write(tmp_path, "money.py", """\
def compute(price_cents, count):
    average_price = price_cents / count
    total = 12.50
    return average_price + total

connection.execute("CREATE TABLE ledger (total DOUBLE, fee NUMERIC, name TEXT)")
""")
    _write(tmp_path, "exact.py", """\
from decimal import Decimal
def compute(price_cents, count):
    total = Decimal("12.50")
    return total
connection.execute("CREATE TABLE ledger (total DECIMAL, name TEXT)")
""")
    findings = integrity_inspect(tmp_path).findings
    assert sorted((item.path, item.line) for item in findings if item.family == "money-as-float") == [
        ("money.py", 2), ("money.py", 3), ("money.py", 6), ("money.py", 6),
    ]


def test_is_test_module_matches_test_paths_not_lookalikes():
    for path in ("test/run.js", "tests/foo.py", "src/foo.test.js", "__tests__/x.py",
                 "test/fixtures/a.js", "spec/thing_spec.py"):
        assert is_test_module(path), path
    for path in ("lib/parser.js", "src/latest.py", "bin/zone38.js", "app/contest.py"):
        assert not is_test_module(path), path


def test_boundary_findings_downweighted_in_test_modules_only():
    base = dict(epistemic_level="CODE FACT", description="path traversal via open",
                controllability="UNDETERMINED", exploitability="NOT_ASSESSED")
    # Real production module: unchanged (MEDIUM under UNDETERMINED controllability).
    assert severity_for("src/app.py", family="path-traversal", **base) == "MEDIUM"
    # Same finding inside a test module: down-weighted to LOW.
    assert severity_for("test/run.js", family="path-traversal", **base) == "LOW"
    assert severity_for("test/run.js", family="parser-boundary", **base) == "LOW"
    # Other families are NOT down-weighted in tests (a hardcoded credential still matters).
    assert severity_for("test/run.js", family="credential", **base) == "MEDIUM"


def test_downweight_names_the_reason_and_keeps_the_finding():
    item = SimpleNamespace(description="path traversal via open", path="test/run.js",
                           line=10, family="path-traversal", column=None,
                           controllability="UNDETERMINED", exploitability="NOT_ASSESSED")
    finding = _with_severity(_agent_finding("security_auditor", item), family="path-traversal")
    assert finding.severity == "LOW"                    # down-weighted
    assert finding.module_path == "test/run.js"         # present, not suppressed
    assert "test module" in finding.reasoning.lower()   # the degradation is named (honest)
