"""Confidence-scored, assumption-free repository stack detection."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import tomllib
import ast
from fractions import Fraction
from collections import Counter
from pathlib import Path
from typing import Iterable

from forge.models import Evidence, ModuleClass, ModuleRecord, StackFingerprint, TriageManifest

# Repository policy: agents audit authored application/source files only.
# Dependency trees, virtual environments, generated/build output, caches, and
# VCS metadata are never an audit scope. Manifests such as package.json and
# requirements.txt remain eligible because they describe the project.
SKIP_DIRS = {
    ".git", ".venv", "venv", ".tox", ".nox", ".eggs", "site-packages",
    "node_modules", "vendor", "third_party", "dependencies", "dependency",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".next", ".turbo",
    ".yarn", ".pnpm-store", "dist", "build", "target", "reportes",
    "resultados", "results", "artifacts", ".forge-results",
}
SKIP_FILE_NAMES = {".gitignore"}
LANG_EXT = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".rs": "Rust", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".c": "C", ".cpp": "C++", ".cs": "C#"}
MANIFESTS = {
    "pyproject.toml": "Python", "setup.py": "Python", "requirements.txt": "Python", "Pipfile": "Python",
    "package.json": "Node.js", "Cargo.toml": "Rust", "go.mod": "Go", "pom.xml": "Java", "build.gradle": "Java", "Gemfile": "Ruby",
}
BUILD_FILES = {"Makefile": "Make", "CMakeLists.txt": "CMake", "Dockerfile": "Docker", "tox.ini": "tox", "pytest.ini": "pytest", "jest.config.js": "Jest"}
CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci")
GIT_PROBE_TIMEOUT_SECONDS = 5
GIT_HISTORY_TIMEOUT_SECONDS = 30
MAX_AUDIT_FILE_BYTES = 5 * 1024 * 1024


def discover_files(root: str | os.PathLike[str], include_excluded: bool = False) -> list[Path]:
    """Single filesystem walk shared by triage, coverage, and AST agents.

    ``include_excluded`` is only for coverage accounting, which must report
    policy exclusions rather than silently losing them.
    """
    base = Path(root)
    return [p for p in base.rglob("*") if p.is_file() and (include_excluded or not is_excluded_by_policy(p, base))]


def is_excluded_by_policy(path: Path, root: Path) -> bool:
    """Return whether a path is outside the agent audit boundary."""
    return exclusion_reason(path, root) is not None


def exclusion_reason(path: Path, root: Path) -> str | None:
    """Return the declared reason a file is excluded before source parsing.

    Binary content, policy exclusions, and oversized files are materially
    different coverage boundaries.  Keep that distinction available to the
    runtime instead of flattening all three into ``excluded_by_policy``.
    """
    relative = path.relative_to(root)
    if path.name in SKIP_FILE_NAMES or any(part in SKIP_DIRS for part in relative.parts):
        return "excluded_by_policy"
    if is_oversized_file(path):
        return "oversized_file"
    if is_binary_file(path):
        return "binary_file"
    return None


def is_oversized_file(path: Path, limit: int = MAX_AUDIT_FILE_BYTES) -> bool:
    """Keep very large artifacts out of all agents before content reads."""
    try:
        return path.stat().st_size > limit
    except OSError:
        # Accessibility is not a size classification.  Let the reader report
        # the distinct ``unreadable_file`` boundary.
        return False


def is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    """Classify binary files with the stable NUL-byte heuristic.

    A UTF-8 decode of an arbitrary prefix is not a binary test: a valid
    multibyte character can straddle the sample boundary.  That previously
    excluded valid authored source (for example ``bridge.py`` in the Corvus
    stress test) before AST analysis.  Non-UTF-8 text is handled later as its
    own readable-source boundary, never silently relabeled as binary here.
    """
    try:
        with path.open("rb") as handle:
            sample = handle.read(sample_size)
    except OSError:
        # Accessibility is not a binary-content signal.  The later text read
        # records this as ``unreadable_file`` rather than disguising it.
        return False
    if not sample:
        return False
    return b"\x00" in sample

def _files(root: Path) -> list[Path]:
    return discover_files(root)


def _evidence(kind: str, source: str, detail: str) -> Evidence:
    return Evidence(kind=kind, source=source, detail=detail)


def detect_stack(root: Path) -> tuple[StackFingerprint, ...]:
    files = _files(root)
    counts = Counter(LANG_EXT.get(p.suffix.lower()) for p in files)
    total_code = sum(v for k, v in counts.items() if k)
    out: list[StackFingerprint] = []
    for lang, count in sorted(counts.items(), key=lambda x: (-x[1], str(x[0]))):
        if not lang:
            continue
        ev = [_evidence("file_count", "filesystem", f"{lang}: {count} files with extension")]
        manifests = [p.name for p in files if p.name in MANIFESTS and MANIFESTS[p.name] == lang]
        if manifests:
            ev.append(_evidence("manifest", "filesystem", ", ".join(sorted(set(manifests))) + " present"))
        confidence = min(Fraction(99, 100), Fraction(55, 100) * Fraction(count, max(total_code, 1)) + (Fraction(40, 100) if manifests else Fraction(0, 1)))
        out.append(StackFingerprint(name=lang, confidence=confidence, evidence=tuple(ev)))
    for marker in sorted(set(p.as_posix().split("/", 1)[-1] if p.is_file() else p.as_posix() for p in files for _ in [0] if any(c in p.as_posix() for c in CI_MARKERS))):
        out.append(StackFingerprint(name="CI", confidence=Fraction(99, 100), evidence=(_evidence("config", "filesystem", marker + " present"),)))
    return tuple(out)


def _git_epochs(root: Path) -> tuple[dict[str, int], str | None]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "log", "--name-only", "--format=COMMIT:%H %ct", "--"],
            stderr=subprocess.DEVNULL, text=True, timeout=GIT_HISTORY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {}, f"Git history query timed out after {GIT_HISTORY_TIMEOUT_SECONDS} seconds; temporal classification is conservative."
    except (OSError, subprocess.SubprocessError):
        return {}, "Git history unavailable; temporal classification is conservative."
    latest: dict[str, int] = {}
    epoch = None
    for line in out.splitlines():
        if line.startswith("COMMIT:"):
            try:
                epoch = int(line.rsplit(" ", 1)[1])
            except (IndexError, ValueError):
                epoch = None
        elif line and epoch is not None and line not in latest:
            latest[line] = epoch
    return latest, None


def _git_available(root: Path) -> bool:
    try:
        subprocess.check_call(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=GIT_PROBE_TIMEOUT_SECONDS)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


_IMPORT_LINE_TAIL = re.compile(r"(?:import|from|require|use).*")


def _reference_tallies(text: str, stems: set[str]) -> dict[str, int]:
    """Count, in one pass over ``text``, how many import-like line tails mention each stem.

    Replaces a design that ran one `re.findall` full-text scan per module
    (O(total_repo_text_size x number_of_modules)) with a single scan that
    tallies every stem at once (O(total_repo_text_size)). `.` never matches
    a newline here (no DOTALL), so each match is confined to one line, same
    as the per-stem regex it replaces; within that line-tail, only the
    distinct stems present are counted, matching the old per-stem regex's
    one-match-per-qualifying-line behavior.
    """
    if not stems:
        return {}
    stem_pattern = re.compile(r"\b(" + "|".join(re.escape(s) for s in stems) + r")\b")
    tallies: dict[str, int] = {}
    for tail_match in _IMPORT_LINE_TAIL.finditer(text):
        for stem in set(stem_pattern.findall(tail_match.group(0))):
            tallies[stem] = tallies.get(stem, 0) + 1
    return tallies


def _caller_counts(root: Path, paths: Iterable[Path]) -> dict[str, tuple[int, int]]:
    paths = list(paths)
    result: dict[str, tuple[int, int]] = {}
    python_paths = [path for path in paths if path.suffix.lower() == ".py"]
    result.update(_python_caller_counts(root, paths))
    other_paths = [path for path in paths if path.suffix.lower() != ".py"]
    if other_paths:
        text = "\n".join(p.read_text(errors="ignore") for p in _files(root) if p.suffix.lower() in {".js", ".ts", ".rs", ".go", ".java", ".rb"})
        tallies = _reference_tallies(text, {p.stem for p in other_paths})
        for path in other_paths:
            imports = tallies.get(path.stem, 0)
            key = str(path.relative_to(root))
            current = result.get(key, (0, 0))
            result[key] = (max(current[0], imports), max(current[1], imports))
    return result


def _python_module_map(root: Path, paths: Iterable[Path]) -> dict[str, str]:
    modules: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(root)
        parts = list(relative.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if parts:
            modules[".".join(parts)] = str(relative)
    return modules


def _resolve_python_module(module: str, source: Path, module_map: dict[str, str]) -> str | None:
    if module in module_map:
        return module_map[module]
    source_parts = list(source.with_suffix("").parts[:-1])
    for index in range(len(source_parts) + 1):
        candidate = ".".join(source_parts[:index] + module.split("."))
        if candidate in module_map:
            return module_map[candidate]
    return None


def _python_import_targets(node: ast.Import | ast.ImportFrom, source: Path, module_map: dict[str, str]) -> set[str]:
    targets: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            target = _resolve_python_module(alias.name, source, module_map)
            if target:
                targets.add(target)
    else:
        prefix = node.module or ""
        if node.level:
            source_parts = list(source.with_suffix("").parts[:-1])
            source_parts = source_parts[: max(0, len(source_parts) - node.level + 1)]
            prefix = ".".join(source_parts + ([prefix] if prefix else []))
        target = _resolve_python_module(prefix, source, module_map) if prefix else None
        if target:
            targets.add(target)
        for alias in node.names:
            candidate = ".".join(part for part in (prefix, alias.name) if part)
            target = _resolve_python_module(candidate, source, module_map)
            if target:
                targets.add(target)
    return targets


def _python_caller_counts(root: Path, paths: Iterable[Path]) -> dict[str, tuple[int, int]]:
    paths = list(paths)
    module_map = _python_module_map(root, paths)
    references: dict[str, set[str]] = {str(path.relative_to(root)): set() for path in paths}
    for source in (path for path in paths if path.suffix.lower() == ".py"):
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        source_relative = str(source.relative_to(root))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for target in _python_import_targets(node, Path(source_relative), module_map):
                if target != source_relative and target in references:
                    references[target].add(source_relative)
    return {path: (len(callers), len(callers)) for path, callers in references.items()}


def _entry_point_paths(root: Path, paths: Iterable[Path]) -> set[str]:
    """Return source paths that are executable entry points by convention/config."""
    candidates = list(paths)
    entry_points = {
        str(path.relative_to(root))
        for path in candidates
        if path.name in {"__main__.py", "main.py", "conftest.py"}
        or any(part in {"bin", "scripts", "tests"} for part in path.relative_to(root).parts)
    }
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            scripts = data.get("project", {}).get("scripts", {})
            for target in scripts.values():
                module = str(target).split(":", 1)[0].replace(".", "/") + ".py"
                if (root / module).is_file():
                    entry_points.add(module)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, AttributeError):
            pass
    setup_py = root / "setup.py"
    if setup_py.is_file():
        try:
            text = setup_py.read_text(encoding="utf-8", errors="replace")
            for module in re.findall(r"[\"']([A-Za-z_][\w.]*)\s*:[^\"']+[\"']", text):
                relative = module.replace(".", "/") + ".py"
                if (root / relative).is_file():
                    entry_points.add(relative)
        except OSError:
            pass
    return entry_points


def triage(root: str | os.PathLike[str]) -> TriageManifest:
    base = Path(root).resolve()
    files = [p for p in _files(base) if p.suffix.lower() in LANG_EXT]
    callers = _caller_counts(base, files)
    git_ok = _git_available(base)
    git_epochs, git_limitation = _git_epochs(base) if git_ok else ({}, "Git history unavailable; temporal classification is conservative.")
    now = int(time.time())
    entry_point_paths = _entry_point_paths(base, files)
    records: list[ModuleRecord] = []
    seen_hashes: dict[str, str] = {}
    duplicate_paths: set[str] = set()
    for p in files:
        rel = str(p.relative_to(base))
        caller_count, import_count = callers.get(rel, (0, 0))
        content_hash = __import__("hashlib").sha256(p.read_bytes()).hexdigest()
        if content_hash in seen_hashes:
            duplicate_paths.add(rel); duplicate_paths.add(seen_hashes[content_hash])
        else:
            seen_hashes[content_hash] = rel
    for p in files:
        rel = str(p.relative_to(base)); caller_count, import_count = callers.get(rel, (0, 0))
        epoch = git_epochs.get(rel) if git_ok else None
        text = p.read_text(errors="ignore")
        keywords = tuple(sorted(set(re.findall(r"\b(score|verdict|classif(?:y|ication)|decision|gate|validate)\b", text, re.I))))
        age_days = (now - epoch) / 86400 if epoch else None
        if rel in duplicate_paths:
            cls = ModuleClass.DUPLICATE
        elif caller_count > 0 or import_count > 0 or rel in entry_point_paths:
            cls = ModuleClass.CONNECTED_ALIVE
        elif keywords:
            cls = ModuleClass.FOSSIL_HIGH_RISK
        elif age_days is not None and age_days >= 90:
            cls = ModuleClass.FOSSIL_LOW_RISK
        else:
            cls = ModuleClass.DEAD_WEIGHT
        ev = [_evidence("caller_graph", rel, f"{caller_count} caller(s), {import_count} import reference(s)"), _evidence("content", rel, f"decision keywords: {list(keywords)}")]
        if rel in entry_point_paths:
            ev.append(_evidence("entry_point", rel, "recognized executable, test, script, or configured console entry point"))
        if epoch is not None: ev.append(_evidence("git_log", rel, f"last logic-touch epoch {epoch}"))
        records.append(ModuleRecord(rel, LANG_EXT[p.suffix.lower()], cls, epoch, caller_count, import_count, keywords, tuple(ev)))
    summary = Counter(r.module_class.value for r in records)
    limitations = [git_limitation] if git_limitation else []
    return TriageManifest("1.1", "0.1.0", str(base), now, detect_stack(base), tuple(sorted(records, key=lambda r: r.path)), dict(summary), tuple(limitations))


def write_manifest(manifest: TriageManifest, destination: str | os.PathLike[str]) -> None:
    Path(destination).write_text(json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n")
