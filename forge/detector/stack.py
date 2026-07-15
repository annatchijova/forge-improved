"""Confidence-scored, assumption-free repository stack detection."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Iterable

from forge.models import Evidence, ModuleClass, ModuleRecord, StackFingerprint, TriageManifest

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
LANG_EXT = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".rs": "Rust", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".c": "C", ".cpp": "C++", ".cs": "C#"}
MANIFESTS = {
    "pyproject.toml": "Python", "setup.py": "Python", "requirements.txt": "Python", "Pipfile": "Python",
    "package.json": "Node.js", "Cargo.toml": "Rust", "go.mod": "Go", "pom.xml": "Java", "build.gradle": "Java", "Gemfile": "Ruby",
}
BUILD_FILES = {"Makefile": "Make", "CMakeLists.txt": "CMake", "Dockerfile": "Docker", "tox.ini": "tox", "pytest.ini": "pytest", "jest.config.js": "Jest"}
CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci")


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)]


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
        confidence = min(0.99, 0.55 * (count / max(total_code, 1)) + (0.4 if manifests else 0.0))
        out.append(StackFingerprint(name=lang, confidence=round(confidence, 3), evidence=tuple(ev)))
    for marker in sorted(set(p.as_posix().split("/", 1)[-1] if p.is_file() else p.as_posix() for p in files for _ in [0] if any(c in p.as_posix() for c in CI_MARKERS))):
        out.append(StackFingerprint(name="CI", confidence=0.99, evidence=(_evidence("config", "filesystem", marker + " present"),)))
    return tuple(out)


def _git_epochs(root: Path) -> dict[str, int]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "log", "--name-only", "--format=COMMIT:%H %ct", "--"],
            stderr=subprocess.DEVNULL, text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
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
    return latest


def _git_available(root: Path) -> bool:
    try:
        subprocess.check_call(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _caller_counts(root: Path, paths: Iterable[Path]) -> dict[str, tuple[int, int]]:
    text = "\n".join(p.read_text(errors="ignore") for p in _files(root) if p.suffix.lower() in {".py", ".js", ".ts", ".rs", ".go", ".java", ".rb"})
    result = {}
    for p in paths:
        stem = p.stem
        imports = len(re.findall(rf"(?:import|from|require|use).*\b{re.escape(stem)}\b", text))
        callers = max(0, imports - 1 if p.suffix == ".py" else imports)
        result[str(p.relative_to(root))] = (callers, imports)
    return result


def triage(root: str | os.PathLike[str]) -> TriageManifest:
    base = Path(root).resolve()
    files = [p for p in _files(base) if p.suffix.lower() in LANG_EXT]
    callers = _caller_counts(base, files)
    git_ok = _git_available(base)
    git_epochs = _git_epochs(base) if git_ok else {}
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
    limitations = [] if git_ok else ["Git history unavailable; temporal classification is conservative."]
    return TriageManifest("1.0", "0.1.0", str(base), now, detect_stack(base), tuple(sorted(records, key=lambda r: r.path)), dict(summary), tuple(limitations))


def write_manifest(manifest: TriageManifest, destination: str | os.PathLike[str]) -> None:
    Path(destination).write_text(json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n")
