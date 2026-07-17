from forge.agents.security_auditor import audit as security_audit
from forge.agents.web_auditor import audit as web_audit
from forge.agents.integrity_inspector import inspect as integrity_inspect
from forge.models import Evidence, Finding
from forge.runtime import _deduplicate_findings
from forge.severity import severity_for


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


def test_web_path_sanitizer_names_propagate_to_sink(tmp_path):
    _write(tmp_path, "safe.ts", "const slug = path.basename(input);\nconst filename = slug;\nfs.writeFileSync(filename, data);\n")
    _write(tmp_path, "unsafe.ts", "fs.writeFileSync(input, data);\n")
    findings, _ = web_audit(tmp_path)
    assert [(item.path, item.family) for item in findings if item.family == "path-traversal"] == [("unsafe.ts", "path-traversal")]


def test_dedup_identity_collapses_variable_names_but_preserves_occurrences():
    first = Finding("OBSERVED", "CODE FACT", "app.py", "unversioned serialization", (Evidence("source", "app.py:7", "json.dumps(payload)"),), "first")
    second = Finding("OBSERVED", "CODE FACT", "app.py", "unversioned serialization", (Evidence("source", "app.py:7", "json.dumps(report)"),), "second")
    result = _deduplicate_findings([first, second])
    assert len(result) == 1
    assert result[0].occurrences == ("app.py:7", "app.py:7")


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
