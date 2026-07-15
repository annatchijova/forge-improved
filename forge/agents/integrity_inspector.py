"""Determinism and schema-versioning checks, independent of bug hypotheses."""
from __future__ import annotations
import ast, os
from dataclasses import dataclass
from pathlib import Path
from forge.detector.stack import discover_files, triage
from forge.models import ModuleClass

@dataclass(frozen=True)
class AgentScanResult:
    findings: tuple
    examinations: dict[str, str]
    def __iter__(self): return iter(self.findings)
    def __len__(self): return len(self.findings)
    def __eq__(self, other): return tuple(self.findings) == tuple(other) if isinstance(other, (tuple, list)) else super().__eq__(other)

@dataclass(frozen=True)
class IntegrityFinding:
    family: str; path: str; line: int; description: str

def inspect(root: str | os.PathLike[str]) -> tuple[IntegrityFinding, ...]:
    base=Path(root); records=triage(base).modules
    eligible={m.path for m in records if m.module_class is ModuleClass.CONNECTED_ALIVE}
    # Preserve the standalone detector contract for tiny unit fixtures with no
    # live module at all; a real repository with any live module uses the
    # explicit CONNECTED_ALIVE-only policy below.
    if not eligible: eligible={m.path for m in records}
    out=[]; examinations={}
    for p in discover_files(base, include_excluded=True):
        rel=str(p.relative_to(base))
        if any(part in {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"} for part in p.relative_to(base).parts):
            examinations[rel]="excluded_by_policy"; continue
        if rel not in eligible or p.suffix != ".py":
            examinations[rel]="excluded_by_scope"
            continue
        try: tree=ast.parse(p.read_text())
        except (SyntaxError, OSError, UnicodeDecodeError): examinations[rel]="excluded_by_scope"; continue
        for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            decision = any(w in fn.name.lower() for w in ("decision","score","verdict","classif","gate"))
            names = {x.id.lower() for x in ast.walk(fn) if isinstance(x, ast.Name)}
            decision = decision or any(any(w in x for w in ("decision","score","verdict","classif","gate")) for x in names)
            if decision:
                for n in ast.walk(fn):
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "float": out.append(IntegrityFinding("decision-adjacent-float", str(p.relative_to(root)), n.lineno, "non-deterministic arithmetic in a decision-adjacent path"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"dump", "dumps"} and isinstance(n.func.value, ast.Name) and n.func.value.id in {"json","pickle"}:
                data = n.args[0] if n.args else None
                versioned = isinstance(data, ast.Dict) and any(isinstance(k, ast.Constant) and k.value in {"schema_version","version"} for k in data.keys)
                if not versioned: out.append(IntegrityFinding("unversioned-serialization", str(p.relative_to(root)), n.lineno, "unversioned serialization"))
        examinations[rel]="examined_with_findings" if any(x.path == rel for x in out) else "examined_clean"
    return AgentScanResult(tuple(out), examinations)
