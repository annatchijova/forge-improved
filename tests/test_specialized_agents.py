import json
from fractions import Fraction

from forge.agents.archaeologist import assess
from forge.agents.security_auditor import audit
from forge.agents.integrity_inspector import inspect
from forge.detector.stack import SKIP_DIRS, discover_files
from forge.agents.patch_reviewer import review
from forge.orchestrator import run_specialized_pipeline
from forge.severity import severity_for

def write(root, name, text):
    p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text); return p

def test_security_credential_trigger_and_safe_context(tmp_path):
    write(tmp_path, "bad.py", "password = 'real-secret'\n")
    write(tmp_path, "safe.py", "# password = 'real-secret'\npassword = os.getenv('PASSWORD')\n")
    hits = audit(tmp_path)
    assert [(x.path, x.family) for x in hits] == [("bad.py", "hardcoded-credential")]

def test_security_flags_hardcoded_credential_as_getenv_default(tmp_path):
    write(tmp_path, "app.py", "import os\nADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')\n")
    hits = [x for x in audit(tmp_path) if x.family == "hardcoded-credential"]
    assert len(hits) == 1 and "ADMIN_PASSWORD" in hits[0].description

def test_security_ignores_getenv_without_default(tmp_path):
    write(tmp_path, "app.py", "import os\nADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')\n")
    assert not [x for x in audit(tmp_path) if x.family == "hardcoded-credential"]

def test_security_ignores_getenv_placeholder_default(tmp_path):
    write(tmp_path, "app.py", "import os\nADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme')\n")
    assert not [x for x in audit(tmp_path) if x.family == "hardcoded-credential"]

def test_security_ignores_getenv_default_for_non_credential_name(tmp_path):
    write(tmp_path, "app.py", "import os\nTIMEOUT = os.getenv('REQUEST_TIMEOUT', '30')\n")
    assert not [x for x in audit(tmp_path) if x.family == "hardcoded-credential"]

def test_security_flags_unverified_webhook_route(tmp_path):
    write(tmp_path, "app.py", (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/webhooks/payment')\n"
        "def payment_webhook(payload):\n"
        "    connection.execute('UPDATE orders SET status=? WHERE id=?', (payload.status, payload.order_id))\n"
        "    return {'ok': True}\n"
    ))
    hits = [x for x in audit(tmp_path) if x.family == "unverified-webhook"]
    assert len(hits) == 1 and "/webhooks/payment" in hits[0].description

def test_security_ignores_webhook_guarded_by_depends(tmp_path):
    write(tmp_path, "app.py", (
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def require_admin(): return 'admin'\n"
        "@app.post('/webhooks/payment')\n"
        "def payment_webhook(payload, _: str = Depends(require_admin)):\n"
        "    connection.execute('UPDATE orders SET status=? WHERE id=?', (payload.status, payload.order_id))\n"
        "    return {'ok': True}\n"
    ))
    assert not [x for x in audit(tmp_path) if x.family == "unverified-webhook"]

def test_security_ignores_webhook_with_signature_check(tmp_path):
    write(tmp_path, "app.py", (
        "import hmac\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/webhooks/payment')\n"
        "def payment_webhook(payload, request):\n"
        "    if not hmac.compare_digest(request.headers['X-Signature'], expected(payload)):\n"
        "        raise PermissionError()\n"
        "    connection.execute('UPDATE orders SET status=? WHERE id=?', (payload.status, payload.order_id))\n"
        "    return {'ok': True}\n"
    ))
    assert not [x for x in audit(tmp_path) if x.family == "unverified-webhook"]

def test_security_ignores_non_webhook_mutating_route_without_depends(tmp_path):
    # This project's own design keeps checkout intentionally public - a
    # blanket "no Depends()" rule would be a false positive here.
    write(tmp_path, "app.py", (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/checkout')\n"
        "def checkout(payload):\n"
        "    connection.execute(\"INSERT INTO orders(status) VALUES('pending_payment')\")\n"
        "    return {'ok': True}\n"
    ))
    assert not [x for x in audit(tmp_path) if x.family == "unverified-webhook"]

def test_security_deserialization_trigger_and_safe_yaml(tmp_path):
    write(tmp_path, "bad.py", "pickle.load(stream)\nyaml.load(raw)\nmarshal.loads(raw)\n")
    write(tmp_path, "safe.py", "yaml.load(raw, Loader=yaml.SafeLoader)\n# pickle.load(trusted)\n")
    assert sum(x.family == "unsafe-deserialization" for x in audit(tmp_path)) == 3

def test_security_path_trigger_and_normalized_safe_context(tmp_path):
    write(tmp_path, "bad.py", "def read(path):\n    return open(path)\n")
    write(tmp_path, "safe.py", "def read(path):\n    path = os.path.normpath(path)\n    return open(path)\n")
    assert [(x.path, x.family) for x in audit(tmp_path)] == [("bad.py", "path-traversal")]


def test_security_path_normalization_is_scoped_to_each_function(tmp_path):
    write(tmp_path, "mixed.py", """
def safe(path):
    path = os.path.normpath(path)
    return open(path)

def unsafe(path):
    return open(path)
""")
    findings = audit(tmp_path)
    assert [(item.family, item.line) for item in findings] == [("path-traversal", 7)]

def test_pipeline_preserves_security_family_for_severity(tmp_path):
    write(tmp_path, "main.py", "import reader\n")
    write(tmp_path, "reader.py", "def read(path):\n    return open(path)\n")
    run_specialized_pipeline(tmp_path, tmp_path / "out")
    sealed = json.loads((tmp_path / "out/verification-manifest.sealed.json").read_text())
    finding = next(entry["finding"] for entry in sealed["chain"] if entry["finding"]["agent"] == "security_auditor")
    expected = severity_for("reader.py", "CODE FACT", finding["description"], "security_auditor", family="path-traversal")
    assert expected == "HIGH"
    assert finding["severity"] == expected


def test_severity_confidence_caps_potential_critical_impact():
    assert severity_for("runtime.py", "PLAUSIBLE HYPOTHESIS", "path reaches open()", family="path-traversal") == "MEDIUM"
    assert severity_for("runtime.py", "CODE FACT", "path reaches open()", family="path-traversal") == "HIGH"
    assert severity_for("runtime.py", "CONFIRMED BY INDUCTION", "path reaches open()", family="path-traversal") == "CRITICAL"

def test_integrity_float_trigger_and_unversioned_serialization(tmp_path):
    write(tmp_path, "bad.py", "def score(decision):\n    value = float(decision)\n    json.dump({'score': value}, out)\n")
    hits = inspect(tmp_path)
    assert {x.family for x in hits} == {"unversioned-serialization"}

def test_integrity_ignores_unrelated_float_telemetry_but_flags_return_value(tmp_path):
    write(tmp_path, "telemetry.py", "def verdict(response):\n    telemetry = {'score': float(response)}\n    return Verdict(telemetry=telemetry, verdict='BLOCKED')\n")
    write(tmp_path, "genuine.py", "def verdict(response):\n    return float(response) > 0.5\n")
    hits = inspect(tmp_path)
    assert [(x.path, x.family) for x in hits] == [("genuine.py", "decision-adjacent-float")]


def test_integrity_ignores_float_used_only_by_to_dict_serialization(tmp_path):
    write(tmp_path, "result.py", """
class Result:
    def __init__(self, score):
        self.score = score
    def to_dict(self):
        return {"score": float(self.score)}
""")
    assert not [x for x in inspect(tmp_path) if x.family == "decision-adjacent-float"]


def test_integrity_safe_float_and_versioned_serialization(tmp_path):
    write(tmp_path, "safe.py", "def display(value):\n    return float(value)\njson.dump({'schema_version': 1}, out)\n")
    assert [(x.path, x.family) for x in inspect(tmp_path)] == [("safe.py", "decision-adjacent-float")]

def test_integrity_recognizes_versioned_named_payload(tmp_path):
    write(tmp_path, "benchmark.py", "import json\ndef write_benchmark(out):\n    payload = {'benchmark_schema_version': '1.0', 'repositories': []}\n    out.write_text(json.dumps(payload))\n")
    assert not [x for x in inspect(tmp_path) if x.family == "unversioned-serialization"]

def test_integrity_ignores_json_embedded_in_presentation_html(tmp_path):
    write(tmp_path, "forge/report.py", "import json\ndef render(metrics):\n    return f'<pre>{json.dumps(metrics)}</pre>'\n")
    assert not [x for x in inspect(tmp_path) if x.family == "unversioned-serialization"]


def test_integrity_does_not_trust_forge_specific_payload_names(tmp_path):
    write(tmp_path, "unrelated.py", "import json\nmetrics = {'value': 1}\njson.dumps(metrics)\n")
    hits = inspect(tmp_path)
    assert [(item.family, item.path) for item in hits] == [("unversioned-serialization", "unrelated.py")]

def test_integrity_suppresses_decision_adjacent_float_for_ml_domain_paths(tmp_path):
    # Same code, same detector: whether it fires depends only on whether the
    # caller (runtime.py, via infer_domains) marked this path machine_learning.
    write(tmp_path, "signal.py", "def estimate(z):\n    return float(z * 343.0)\n")
    assert [x.family for x in inspect(tmp_path)] == ["decision-adjacent-float"]
    assert not inspect(tmp_path, ml_domain_paths=frozenset({"signal.py"}))

def test_integrity_ml_domain_suppression_is_scoped_to_flagged_paths_only(tmp_path):
    write(tmp_path, "signal.py", "def estimate(z):\n    return float(z * 343.0)\n")
    write(tmp_path, "verdict.py", "def decide(z):\n    return float(z) > 0.5\n")
    hits = inspect(tmp_path, ml_domain_paths=frozenset({"signal.py"}))
    assert [x.path for x in hits] == ["verdict.py"]

def test_integrity_flags_sql_real_column_with_money_shaped_name(tmp_path):
    write(tmp_path, "db.py", (
        "import sqlite3\n"
        "def init(conn):\n"
        "    conn.executescript('CREATE TABLE t (discount_percent REAL NOT NULL DEFAULT 0)')\n"
    ))
    hits = [x for x in inspect(tmp_path) if x.family == "money-as-float"]
    assert len(hits) == 1 and "discount_percent" in hits[0].description

def test_integrity_ignores_sql_real_column_with_unrelated_name(tmp_path):
    write(tmp_path, "db.py", (
        "import sqlite3\n"
        "def init(conn):\n"
        "    conn.executescript('CREATE TABLE t (latitude REAL NOT NULL DEFAULT 0)')\n"
    ))
    assert not [x for x in inspect(tmp_path) if x.family == "money-as-float"]

def test_integrity_flags_round_over_division_on_money_shaped_value(tmp_path):
    write(tmp_path, "checkout.py", (
        "def line_total(product):\n"
        "    return round(product['price_cents'] * (1 - product['discount_percent'] / 100))\n"
    ))
    hits = [x for x in inspect(tmp_path) if x.family == "money-as-float"]
    assert len(hits) == 1

def test_integrity_ignores_round_over_division_on_unrelated_value(tmp_path):
    write(tmp_path, "physics.py", (
        "def average(samples):\n"
        "    return round(sum(samples) / len(samples))\n"
    ))
    assert not [x for x in inspect(tmp_path) if x.family == "money-as-float"]

def test_integrity_ignores_money_computed_with_fraction_not_division(tmp_path):
    write(tmp_path, "checkout.py", (
        "from fractions import Fraction\n"
        "def line_total(product):\n"
        "    discount = Fraction(product['discount_percent_bp'], 10000)\n"
        "    return round(product['price_cents'] * (1 - discount))\n"
    ))
    assert not [x for x in inspect(tmp_path) if x.family == "money-as-float"]

def test_shared_discovery_excludes_venv_from_security(tmp_path):
    write(tmp_path, "main.py", "x = 1\n")
    write(tmp_path, ".venv/site.py", "password = 'leaked'\n")
    result = audit(tmp_path)
    assert not result.findings
    assert result.examinations[".venv/site.py"] == "excluded_by_policy"

def test_security_broader_scope_but_integrity_live_scope_only(tmp_path):
    write(tmp_path, "main.py", "import live\ndef score(decision):\n    return float(decision)\n")
    write(tmp_path, "live.py", "password = 'live-secret'\ndef score(decision):\n    return float(decision)\n")
    write(tmp_path, "fossil.py", "password = 'fossil-secret'\ndef score(decision):\n    return float(decision)\n")
    security = audit(tmp_path)
    integrity = inspect(tmp_path)
    assert {x.path for x in security.findings if x.family == "hardcoded-credential"} == {"live.py", "fossil.py"}
    assert {x.path for x in integrity.findings if x.family == "decision-adjacent-float"} == {"main.py", "live.py"}
    assert integrity.examinations["fossil.py"] == "excluded_by_scope"

def test_clean_connected_module_is_explicitly_examined(tmp_path):
    write(tmp_path, "main.py", "import clean\n")
    write(tmp_path, "clean.py", "VALUE = 1\n")
    security = audit(tmp_path)
    integrity = inspect(tmp_path)
    assert security.examinations["clean.py"] == "examined_clean"
    assert integrity.examinations["clean.py"] == "examined_clean"

def test_all_agents_share_exact_skip_directory_policy(tmp_path):
    write(tmp_path, "main.py", "import clean\n")
    for directory in SKIP_DIRS:
        write(tmp_path, f"{directory}/hidden.py", "password = 'secret'\n")
    discovered = {str(p.relative_to(tmp_path)) for p in discover_files(tmp_path)}
    security = audit(tmp_path)
    integrity = inspect(tmp_path)
    for directory in SKIP_DIRS:
        hidden = f"{directory}/hidden.py"
        assert hidden not in discovered
        assert security.examinations[hidden] == "excluded_by_policy"
        assert integrity.examinations[hidden] == "excluded_by_policy"

def test_scope_policy_excludes_dependencies_virtualenv_and_gitignore_but_keeps_manifests(tmp_path):
    write(tmp_path, "main.py", "import live\n")
    write(tmp_path, "live.py", "VALUE = 1\n")
    write(tmp_path, ".gitignore", "*.secret\n")
    write(tmp_path, ".venv/lib/python3.12/site.py", "password = 'secret'\n")
    write(tmp_path, "node_modules/pkg/index.js", "password = 'secret'\n")
    write(tmp_path, "vendor/pkg.py", "password = 'secret'\n")
    write(tmp_path, "package.json", "{}\n")
    write(tmp_path, "requirements.txt", "pytest\n")
    discovered = {str(p.relative_to(tmp_path)) for p in discover_files(tmp_path)}
    all_files = {str(p.relative_to(tmp_path)) for p in discover_files(tmp_path, include_excluded=True)}
    assert ".gitignore" not in discovered
    assert {".venv/lib/python3.12/site.py", "node_modules/pkg/index.js", "vendor/pkg.py"}.isdisjoint(discovered)
    assert {".gitignore", ".venv/lib/python3.12/site.py", "node_modules/pkg/index.js", "vendor/pkg.py"} <= all_files
    assert {"package.json", "requirements.txt"} <= discovered
    result = audit(tmp_path)
    for excluded in (".gitignore", ".venv/lib/python3.12/site.py", "node_modules/pkg/index.js", "vendor/pkg.py"):
        assert result.examinations[excluded] == "excluded_by_policy"


def test_scope_policy_excludes_prior_audit_output_from_all_agents(tmp_path):
    write(tmp_path, "main.py", "VALUE = 1\n")
    for directory in ("resultados", "results", "artifacts", ".forge-results"):
        write(tmp_path, f"{directory}/prior.json", '{"findings": [{"severity": "CRITICAL"}]}\n')
    discovered = {str(path.relative_to(tmp_path)) for path in discover_files(tmp_path)}
    result = audit(tmp_path)
    assert {f"{directory}/prior.json" for directory in ("resultados", "results", "artifacts", ".forge-results")}.isdisjoint(discovered)
    for directory in ("resultados", "results", "artifacts", ".forge-results"):
        assert result.examinations[f"{directory}/prior.json"] == "excluded_by_policy"


def test_scope_policy_excludes_binary_files_without_decoding_them(tmp_path):
    write(tmp_path, "main.py", "VALUE = 1\n")
    binary = tmp_path / "assets" / "image.bin"
    binary.parent.mkdir()
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00" + b"x" * 8192)
    discovered = {str(path.relative_to(tmp_path)) for path in discover_files(tmp_path)}
    result = audit(tmp_path)
    assert "assets/image.bin" not in discovered
    assert result.examinations["assets/image.bin"] == "excluded_by_policy"


def test_scope_policy_excludes_oversized_text_before_agent_reads(tmp_path):
    write(tmp_path, "main.py", "VALUE = 1\n")
    oversized = tmp_path / "generated" / "bundle.js"
    oversized.parent.mkdir()
    with oversized.open("wb") as handle:
        handle.truncate(5 * 1024 * 1024 + 1)
    discovered = {str(path.relative_to(tmp_path)) for path in discover_files(tmp_path)}
    result = audit(tmp_path)
    assert "generated/bundle.js" not in discovered
    assert result.examinations["generated/bundle.js"] == "excluded_by_policy"


def test_agents_preserve_syntax_failure_status_instead_of_calling_it_scope_exclusion(tmp_path):
    write(tmp_path, "broken.py", "def broken(:\n    return 1\n")
    security = audit(tmp_path)
    integrity = inspect(tmp_path)
    assert security.examinations["broken.py"] == "syntax_error"
    assert integrity.examinations["broken.py"] == "syntax_error"

def test_archaeologist_adds_deletion_judgment(tmp_path):
    write(tmp_path, "dead.py", "x = 1\n")
    result = assess(tmp_path)
    assert "dead.py" in result.deletion_judgments

def test_patch_reviewer_is_optional_and_separate():
    result = review("@@ -1 +1 @@\n-old\n+new\n", "missing", "def run():\n    return 1\n")
    assert result.changed_lines == 2 and result.flags

def test_patch_reviewer_ratio_is_exact_fraction_not_float():
    diff = "@@ -1,2 +1,2 @@\n-return 1\n+return 2\n def run():\n"
    result = review(diff, "run adjustment", "", "def run():\n    return 1\n    return 2\n")
    assert isinstance(result.ratio, Fraction), f"ratio must be an exact Fraction, not {type(result.ratio)}"

def test_patch_reviewer_intent_match_does_not_flag(tmp_path):
    before = "def run():\n    return 1\n"
    after = "def run():\n    return 2\n"
    diff = "@@ -1,2 +1,2 @@\n def run():\n-    return 1\n+    return 2\n"
    result = review(diff, "run behavior change", before, after)
    assert result.touched_scopes == ("run",)
    assert not result.flags

def test_patch_reviewer_flags_scope_mismatch_with_stated_intent(tmp_path):
    before = "def unrelated():\n    return 1\n"
    after = "def unrelated():\n    return 2\n"
    diff = "@@ -1,2 +1,2 @@\n def unrelated():\n-    return 1\n+    return 2\n"
    result = review(diff, "database migration", before, after)
    assert result.flags == ("changed lines do not match stated intent",)


def test_patch_reviewer_raises_named_error_for_malformed_source():
    import pytest
    from forge.agents.patch_reviewer import PatchReviewInputError

    with pytest.raises(PatchReviewInputError, match="not valid Python"):
        review("", "syntax", after="def broken(:")
