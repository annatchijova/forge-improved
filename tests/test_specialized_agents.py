from forge.agents.archaeologist import assess
from forge.agents.security_auditor import audit
from forge.agents.integrity_inspector import inspect
from forge.agents.patch_reviewer import review

def write(root, name, text):
    p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text); return p

def test_security_credential_trigger_and_safe_context(tmp_path):
    write(tmp_path, "bad.py", "password = 'real-secret'\n")
    write(tmp_path, "safe.py", "# password = 'real-secret'\npassword = os.getenv('PASSWORD')\n")
    hits = audit(tmp_path)
    assert [(x.path, x.family) for x in hits] == [("bad.py", "hardcoded-credential")]

def test_security_deserialization_trigger_and_safe_yaml(tmp_path):
    write(tmp_path, "bad.py", "pickle.load(stream)\nyaml.load(raw)\nmarshal.loads(raw)\n")
    write(tmp_path, "safe.py", "yaml.load(raw, Loader=yaml.SafeLoader)\n# pickle.load(trusted)\n")
    assert sum(x.family == "unsafe-deserialization" for x in audit(tmp_path)) == 3

def test_security_path_trigger_and_normalized_safe_context(tmp_path):
    write(tmp_path, "bad.py", "def read(path):\n    return open(path)\n")
    write(tmp_path, "safe.py", "def read(path):\n    path = os.path.normpath(path)\n    return open(path)\n")
    assert [(x.path, x.family) for x in audit(tmp_path)] == [("bad.py", "path-traversal")]

def test_integrity_float_trigger_and_unversioned_serialization(tmp_path):
    write(tmp_path, "bad.py", "def score(decision):\n    value = float(decision)\n    json.dump({'score': value}, out)\n")
    hits = inspect(tmp_path)
    assert {x.family for x in hits} == {"decision-adjacent-float", "unversioned-serialization"}

def test_integrity_safe_float_and_versioned_serialization(tmp_path):
    write(tmp_path, "safe.py", "def display(value):\n    return float(value)\njson.dump({'schema_version': 1}, out)\n")
    assert inspect(tmp_path) == ()

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

def test_archaeologist_adds_deletion_judgment(tmp_path):
    write(tmp_path, "dead.py", "x = 1\n")
    result = assess(tmp_path)
    assert "dead.py" in result.deletion_judgments

def test_patch_reviewer_is_optional_and_separate():
    result = review("@@ -1 +1 @@\n-old\n+new\n", "missing", "def run():\n    return 1\n")
    assert result.changed_lines == 2 and result.flags
