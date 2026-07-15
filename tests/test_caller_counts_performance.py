"""Regression coverage for the _caller_counts() O(n^2) -> O(n) rewrite.

forge.detector.stack._caller_counts() used to build the repo's concatenated
text once, then run one re.findall() full-text scan PER module in `paths` -
O(total_repo_text_size x number_of_modules). It now runs a single combined
scan and tallies every stem at once. These tests pin down two things
independently: (1) the new implementation produces identical
(caller_count, import_count) values to the old one on representative
fixtures, and (2) the number of regex scans no longer grows with the number
of modules.
"""
import re
from pathlib import Path

from forge.detector.stack import _caller_counts, _files


def _reference_caller_counts(root: Path, paths):
    """The original, quadratic implementation - kept only as a parity oracle."""
    text = "\n".join(
        p.read_text(errors="ignore") for p in _files(root)
        if p.suffix.lower() in {".py", ".js", ".ts", ".rs", ".go", ".java", ".rb"}
    )
    result = {}
    for p in paths:
        stem = p.stem
        imports = len(re.findall(rf"(?:import|from|require|use).*\b{re.escape(stem)}\b", text))
        callers = max(0, imports - 1 if p.suffix == ".py" else imports)
        result[str(p.relative_to(root))] = (callers, imports)
    return result


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_caller_counts_matches_reference_on_cross_import_fixture(tmp_path):
    _write(tmp_path, "main.py", "import a\nimport b\nimport c\n")
    _write(tmp_path, "a.py", "import b\nx = 1\n")
    _write(tmp_path, "b.py", "x = 2\n")
    _write(tmp_path, "c.py", "from a import thing\nx = 3\n")
    _write(tmp_path, "orphan.py", "x = 4\n")
    paths = sorted(tmp_path.glob("*.py"))
    assert _caller_counts(tmp_path, paths) == _reference_caller_counts(tmp_path, paths)


def test_caller_counts_matches_reference_with_duplicate_stems_in_different_dirs(tmp_path):
    _write(tmp_path, "main.py", "import utils\n")
    _write(tmp_path, "utils.py", "x = 1\n")
    _write(tmp_path, "sub/utils.py", "x = 2\n")
    paths = sorted(tmp_path.rglob("*.py"))
    assert _caller_counts(tmp_path, paths) == _reference_caller_counts(tmp_path, paths)


def test_caller_counts_matches_reference_on_multi_language_fixture(tmp_path):
    _write(tmp_path, "index.js", "const util = require('./util');\nconst other = require('./other');\n")
    _write(tmp_path, "util.js", "module.exports = () => 1;\n")
    _write(tmp_path, "other.js", "module.exports = () => 2;\n")
    _write(tmp_path, "unused.js", "module.exports = () => 3;\n")
    paths = sorted(tmp_path.glob("*.js"))
    assert _caller_counts(tmp_path, paths) == _reference_caller_counts(tmp_path, paths)


def test_caller_counts_matches_reference_with_multiple_keywords_and_stems_on_one_line(tmp_path):
    # Two import-like keywords ("import" and "from") on the same physical
    # line, plus a trailing comment that itself mentions two more stems via
    # a third keyword ("use") - the exact shape that would break a naive
    # single-match-per-line rewrite of _reference_tallies().
    _write(tmp_path, "main.py", "import a; from b import c  # also see d and use e\n")
    for name in ("a", "b", "c", "d", "e"):
        _write(tmp_path, f"{name}.py", f"x = {name!r}\n")
    _write(tmp_path, "unrelated.py", "x = 0\n")
    paths = sorted(tmp_path.glob("*.py"))
    old = _reference_caller_counts(tmp_path, paths)
    new = _caller_counts(tmp_path, paths)
    assert new == old
    # Guard against a degenerate rewrite that silently returns all-zero
    # counts and would otherwise make the equality assertion above pass
    # trivially.
    assert any(count[1] > 0 for count in old.values())


def test_caller_counts_regex_scan_count_does_not_scale_with_module_count(tmp_path, monkeypatch):
    original_findall = re.findall
    calls = {"n": 0}

    def counting_findall(*args, **kwargs):
        calls["n"] += 1
        return original_findall(*args, **kwargs)

    monkeypatch.setattr(re, "findall", counting_findall)

    def build(root, n):
        for i in range(n):
            _write(root, f"mod{i}.py", f"import mod{(i + 1) % n}\nx = {i}\n")

    small_root = tmp_path / "small"; small_root.mkdir(); build(small_root, 10)
    large_root = tmp_path / "large"; large_root.mkdir(); build(large_root, 60)

    calls["n"] = 0
    _caller_counts(small_root, sorted(small_root.glob("*.py")))
    small_calls = calls["n"]

    calls["n"] = 0
    _caller_counts(large_root, sorted(large_root.glob("*.py")))
    large_calls = calls["n"]

    # The old implementation called re.findall exactly once per module (10 vs
    # 60). The new one performs a small, fixed number of scans regardless of
    # module count - it must not grow anywhere near proportionally.
    assert large_calls <= small_calls + 2, (
        f"re.findall call count grew from {small_calls} (10 modules) to "
        f"{large_calls} (60 modules) - this must not scale with module count"
    )
