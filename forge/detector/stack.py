"""Confidence-scored, assumption-free repository stack detection."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from fractions import Fraction
from collections import Counter
from pathlib import Path
from typing import Iterable

from forge.models import Evidence, ModuleClass, ModuleRecord, StackFingerprint, TriageManifest

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", "reportes"}
LANG_EXT = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".rs": "Rust", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".c": "C", ".cpp": "C++", ".cs": "C#"}
MANIFESTS = {
    "pyproject.toml": "Python", "setup.py": "Python", "requirements.txt": "Python", "Pipfile": "Python",
    "package.json": "Node.js", "Cargo.toml": "Rust", "go.mod": "Go", "pom.xml": "Java", "build.gradle": "Java", "Gemfile": "Ruby",
}
BUILD_FILES = {"Makefile": "Make", "CMakeLists.txt": "CMake", "Dockerfile": "Docker", "tox.ini": "tox", "pytest.ini": "pytest", "jest.config.js": "Jest"}
CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci")
GIT_PROBE_TIMEOUT_SECONDS = 5
GIT_HISTORY_TIMEOUT_SECONDS = 30


def discover_files(root: str | os.PathLike[str], include_excluded: bool = False) -> list[Path]:
    """Single filesystem walk shared by triage, coverage, and AST agents.

    ``include_excluded`` is only for coverage accounting, which must report
    policy exclusions rather than silently losing them.
    """
    base = Path(root)
    return [p for p in base.rglob("*") if p.is_file() and (include_excluded or not any(part in SKIP_DIRS for part in p.relative_to(base).parts))]

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
    text = "\n".join(p.read_text(errors="ignore") for p in _files(root) if p.suffix.lower() in {".py", ".js", ".ts", ".rs", ".go", ".java", ".rb"})
    paths = list(paths)
    tallies = _reference_tallies(text, {p.stem for p in paths})
    result = {}
    for p in paths:
        imports = tallies.get(p.stem, 0)
        callers = max(0, imports - 1 if p.suffix == ".py" else imports)
        result[str(p.relative_to(root))] = (callers, imports)
    return result


def triage(root: str | os.PathLike[str]) -> TriageManifest:
    base = Path(root).resolve()
    files = [p for p in _files(base) if p.suffix.lower() in LANG_EXT]
    callers = _caller_counts(base, files)
    git_ok = _git_available(base)
    git_epochs, git_limitation = _git_epochs(base) if git_ok else ({}, "Git history unavailable; temporal classification is conservative.")
    now = int(time.time())
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
        elif caller_count > 0 or import_count > 0 or p.name in {"__main__.py", "main.py"}:
            cls = ModuleClass.CONNECTED_ALIVE
        elif keywords:
            cls = ModuleClass.FOSSIL_HIGH_RISK
        elif age_days is not None and age_days >= 90:
            cls = ModuleClass.FOSSIL_LOW_RISK
        else:
            cls = ModuleClass.DEAD_WEIGHT
        ev = [_evidence("caller_graph", rel, f"{caller_count} caller(s), {import_count} import reference(s)"), _evidence("content", rel, f"decision keywords: {list(keywords)}")]
        if epoch is not None: ev.append(_evidence("git_log", rel, f"last logic-touch epoch {epoch}"))
        records.append(ModuleRecord(rel, LANG_EXT[p.suffix.lower()], cls, epoch, caller_count, import_count, keywords, tuple(ev)))
    summary = Counter(r.module_class.value for r in records)
    limitations = [git_limitation] if git_limitation else []
    return TriageManifest("1.1", "0.1.0", str(base), now, detect_stack(base), tuple(sorted(records, key=lambda r: r.path)), dict(summary), tuple(limitations))


def write_manifest(manifest: TriageManifest, destination: str | os.PathLike[str]) -> None:
    Path(destination).write_text(json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n")
