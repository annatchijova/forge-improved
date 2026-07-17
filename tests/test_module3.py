from forge.detector.stack import triage
from forge.hypotheses import _candidates, generate_hypotheses
from forge.verification import verify_hypotheses
from forge.verification import _call_at
import ast
from forge.models import Hypothesis, HypothesesManifest
from forge.verification import _description_call_name

def test_ast_overrides_proximity_false_negative(tmp_path):
    (tmp_path / "main.py").write_text("import subprocess\ndef run(cmd):\n    try:\n        harmless = 1\n    except Exception:\n        harmless = 2\n    return subprocess.run(cmd)\n")
    manifest = HypothesesManifest("1.0", "0.1.0", "1.0", str(tmp_path), 0, (Hypothesis("main.py", 1, "subprocess.run call", (4,), "force failure"),), ("main.py",))
    result = verify_hypotheses(manifest)
    assert result.findings
    assert not result.discarded

def test_call_at_disambiguates_nested_calls_on_same_line():
    tree = ast.parse("foo(bar())\n")
    assert ast.unparse(_call_at(tree, 1, "foo").func) == "foo"
    assert ast.unparse(_call_at(tree, 1, "bar").func) == "bar"

def test_call_name_extraction_fallback_is_explicit():
    assert _description_call_name("a description without the expected call marker") is None
    tree = ast.parse("foo(bar())\n")
    # None intentionally means first call on the line; this is a known limitation.
    assert ast.unparse(_call_at(tree, 1).func) == "foo"

def test_ast_discards_actually_enclosed_subprocess(tmp_path):
    (tmp_path / "main.py").write_text("import subprocess\ndef run():\n    try:\n        return subprocess.run(['trusted'], check=True)\n    except subprocess.SubprocessError as exc:\n        raise RuntimeError from exc\n")
    manifest = HypothesesManifest("1.0", "0.1.0", "1.0", str(tmp_path), 0, (Hypothesis("main.py", 1, "subprocess.run call", (4,), "force failure"),), ("main.py",))
    result = verify_hypotheses(manifest)
    assert not result.findings
    assert result.discarded

def test_parser_known_handler_is_benign_but_generic_is_not(tmp_path):
    (tmp_path / "main.py").write_text("import json\ndef load(raw):\n    try:\n        return json.loads(raw)\n    except json.JSONDecodeError:\n        return None\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert result.ast_verified_families == ("subprocess", "parser", "float comparison", "eval/exec")
    assert not result.findings


def test_parser_broad_handler_with_explicit_degradation_is_benign(tmp_path):
    (tmp_path / "main.py").write_text(
        "import json\n"
        "def analyze(raw):\n"
        "    try:\n"
        "        return json.loads(raw)\n"
        "    except Exception:\n"
        "        return {'error': 'invalid input'}\n"
    )
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert not result.findings


def test_parser_exception_handler_that_swallows_is_not_a_benign_boundary():
    hypotheses, _ = _candidates(
        "fixture.py",
        (
            "import json\n",
            "def analyze(raw):\n",
            "    try:\n",
            "        return json.loads(raw)\n",
            "    except Exception:\n",
            "        pass\n",
        ),
        "Python",
    )
    assert len(hypotheses) == 1


def test_local_lexicon_load_is_not_treated_as_external_parser_input():
    hypotheses, _ = _candidates(
        "detector.py",
        (
            "from pathlib import Path\n",
            "import json\n",
            "_LEXICON_DIR = Path(__file__).parent / 'lexicon'\n",
            "def _load():\n",
            "    with open(_LEXICON_DIR / 'data.json') as f:\n",
            "        return json.load(f)\n",
        ),
        "Python",
    )
    assert hypotheses == []

def test_eval_literal_benign_and_variable_is_finding(tmp_path):
    (tmp_path / "main.py").write_text("def run(expr):\n    return eval(expr)\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert result.findings and "eval" in result.findings[0].description
    (tmp_path / "main.py").write_text("def run():\n    return eval('1 + 1')\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert not result.findings and result.discarded

def test_eval_literal_with_dangerous_content_is_not_discarded(tmp_path):
    (tmp_path / "main.py").write_text('def run():\n    return eval(\'os.system("rm -rf /")\')\n')
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert result.findings, (
        "a literal eval/exec argument that itself invokes OS command execution "
        "must not be auto-discarded as benign just because it is a constant string"
    )
    assert not result.discarded


def test_eval_induction_confirms_only_when_its_in_sandbox_sentinel_executes(tmp_path):
    (tmp_path / "main.py").write_text("def run(expr):\n    return eval(expr)\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)), induce=True)
    assert result.findings[0].epistemic_level == "CONFIRMED BY INDUCTION"
    assert result.induction[0]["family"] == "eval/exec"
    assert "sentinel" in result.induction[0]["detail"]

def test_float_tolerance_is_benign_exact_float_remains_candidate(tmp_path):
    (tmp_path / "main.py").write_text("import math\ndef score(x):\n    return math.isclose(x, 1.0, abs_tol=0.01)\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)))
    assert not result.findings


def test_float_threshold_ignores_telemetry_comparison_not_returned(tmp_path):
    (tmp_path / "main.py").write_text("def score_report(value):\n    score = float(value) > 0.5\n    telemetry = {'score': score}\n    return 'ok'\n")
    result = generate_hypotheses(triage(tmp_path))
    assert not [item for item in result.hypotheses if "binary float threshold" in item.description]


def test_math_isclose_phrase_inside_string_is_not_a_hypothesis():
    # The detector's own surface pattern is a string literal, not a real call.
    hypotheses, _ = _candidates("fixture.py", ('if "math.isclose" in stripped:\n',), "Python")
    assert hypotheses == []


def test_zero_argument_eval_method_call_is_not_a_hypothesis():
    # model.eval() is PyTorch's evaluation-mode convention (no argument, no
    # code execution), not a call to the eval()/exec() builtins - which
    # always take at least one argument (eval() with none is a SyntaxError).
    hypotheses, _ = _candidates("fixture.py", ("model.eval()\n",), "Python")
    assert not [h for h in hypotheses if "dynamic evaluation" in h.description]


def test_real_eval_call_on_an_object_is_still_a_hypothesis():
    # Only the zero-argument shape is excluded; something.eval(expr) still
    # crosses a data-to-code boundary and must still be flagged.
    hypotheses, _ = _candidates("fixture.py", ("sandbox.eval(user_expr)\n",), "Python")
    assert [h for h in hypotheses if "dynamic evaluation" in h.description]


def test_risk_shaped_strings_do_not_create_regex_hypotheses():
    source = (
        'note = "subprocess.run(cmd)"\n',
        'note = "json.loads(raw)"\n',
        'note = "score > 0.5"\n',
        'note = "eval(expr)"\n',
    )
    hypotheses, _ = _candidates("fixture.py", source, "Python")
    assert hypotheses == []


def test_shell_true_is_a_distinct_hypothesis_family():
    hypotheses, _ = _candidates("fixture.py", ("subprocess.call(cmd, shell=True)\n",), "Python")
    assert len(hypotheses) == 1
    assert "shell=True" in hypotheses[0].description


def test_all_candidates_are_verified_instead_of_a_silent_five_item_cap(tmp_path):
    (tmp_path / "main.py").write_text(
        "def run(a, b, c, d, e, f, g):\n"
        "    eval(a)\n"
        "    eval(b)\n"
        "    eval(c)\n"
        "    eval(d)\n"
        "    eval(e)\n"
        "    eval(f)\n"
        "    eval(g)\n"
    )
    hypotheses = generate_hypotheses(triage(tmp_path))
    assert len(hypotheses.hypotheses) == 7
    assert not [item for item in hypotheses.limitations if "omitted" in item.lower()]
    assert len(verify_hypotheses(hypotheses).findings) == 7


def test_parser_induction_does_not_confirm_opaque_failure_outside_hypothesized_call(tmp_path):
    (tmp_path / "main.py").write_text("def parse(raw):\n    raise RuntimeError('opaque parser failure')\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)), induce=True)
    assert result.findings
    assert result.findings[0].epistemic_level == "PLAUSIBLE HYPOTHESIS"
    assert result.induction[0]["status"] == "ERROR_PATH_REACHABLE"


def test_parser_induction_confirms_opaque_failure_at_hypothesized_call(tmp_path):
    (tmp_path / "main.py").write_text("def parse(raw):\n    raise RuntimeError('opaque parser failure')\n")
    manifest = HypothesesManifest("1.0", "0.1.0", "1.0", str(tmp_path), 0, (Hypothesis("main.py", 1, "The parser call `json.loads(raw)` has no nearby exception handling.", (2,), "force failure"),), ("main.py",))
    result = verify_hypotheses(manifest, induce=True)
    assert result.findings
    assert result.findings[0].epistemic_level == "CONFIRMED BY INDUCTION"
    assert result.induction[0]["status"] == "CONFIRMED BY INDUCTION"


def test_parser_induction_respects_named_boundary_handler(tmp_path):
    (tmp_path / "main.py").write_text("import json\ndef load(raw):\n    try:\n        return json.loads(raw)\n    except json.JSONDecodeError:\n        return None\n")
    result = verify_hypotheses(generate_hypotheses(triage(tmp_path)), induce=True)
    assert not result.findings
    assert not result.induction


def test_parser_induction_loads_relative_imports_as_a_package(tmp_path):
    package = tmp_path / "detectors"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "base.py").write_text("def marker(): return True\n")
    (package / "sample.py").write_text(
        "from .base import marker\n"
        "import json\n"
        "def parse(raw):\n"
        "    return json.loads(raw)\n"
        "def analyze(text):\n"
        "    return parse('{not valid json')\n"
    )
    manifest = HypothesesManifest(
        "1.0", "0.1.0", "1.0", str(tmp_path), 0,
        (Hypothesis("detectors/sample.py", 4, "The parser call `json.loads(raw)` has no nearby exception handling.", (4,), "feed malformed input"),),
        ("detectors/sample.py",),
    )
    result = verify_hypotheses(manifest, induce=True)
    assert not result.findings
    assert result.induction[0]["status"] == "FALSIFIED"
