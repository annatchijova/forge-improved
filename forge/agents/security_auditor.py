"""AST-only security checks with conservative, family-specific safe criteria."""
from __future__ import annotations
import ast, os, re
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
class SecurityFinding:
    family: str; path: str; line: int; description: str

_CRED = re.compile(r"(password|passwd|secret|token|api[_-]?key|credential)", re.I)
_PLACEHOLDER = re.compile(r"^(changeme|change_me|example|placeholder|your[_ -].*|<.*>)$", re.I)

def _safe_credential(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "getenv"

def _assigned(tree):
    for n in ast.walk(tree):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AnnAssign) else []
        value = getattr(n, "value", None)
        for target in targets:
            if isinstance(target, ast.Name) and _CRED.search(target.id) and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value and not _PLACEHOLDER.match(value.value) and not _safe_credential(value):
                yield SecurityFinding("hardcoded-credential", "", n.lineno, f"non-empty credential-like string assigned to {target.id}")

def _deserialization(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute) or not isinstance(n.func.value, ast.Name): continue
        mod, name = n.func.value.id, n.func.attr
        if (mod, name) in {("pickle", "loads"), ("pickle", "load"), ("marshal", "loads")}:
            yield SecurityFinding("unsafe-deserialization", "", n.lineno, f"{mod}.{name} accepts serialized data without a safe structural boundary")
        elif mod == "yaml" and name == "load":
            safe = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and isinstance(k.value.value, ast.Name) and k.value.value.id == "yaml" and k.value.attr == "SafeLoader" for k in n.keywords)
            if not safe: yield SecurityFinding("unsafe-deserialization", "", n.lineno, "yaml.load lacks Loader=yaml.SafeLoader")

def _paths(tree):
    functions = [f for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
    params = {a.arg for f in functions for a in f.args.args}
    normalized = {t.id for f in functions for n in ast.walk(f) if isinstance(n, ast.Assign)
                  and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                  and n.value.func.attr in {"normpath", "realpath"}
                  for t in n.targets if isinstance(t, ast.Name)}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "os" and n.func.attr == "path" and n.args and any(isinstance(x, ast.Name) and x.id in params and x.id not in normalized for x in n.args):
            yield SecurityFinding("path-traversal", "", n.lineno, "parameter reaches os.path operation without proven normalization")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open" and n.args and any(isinstance(x, ast.Name) and x.id in params and x.id not in normalized for x in n.args):
            yield SecurityFinding("path-traversal", "", n.lineno, "parameter reaches open() without proven normalization")

def audit(root: str | os.PathLike[str]) -> tuple[SecurityFinding, ...]:
    base=Path(root); eligible={m.path for m in triage(base).modules if m.module_class in {ModuleClass.CONNECTED_ALIVE, ModuleClass.FOSSIL_HIGH_RISK, ModuleClass.DEAD_WEIGHT}}
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
        for f in (*_assigned(tree), *_deserialization(tree), *_paths(tree)): out.append(SecurityFinding(f.family, str(p.relative_to(root)), f.line, f.description))
        examinations[rel]="examined_with_findings" if any(x.path == rel for x in out) else "examined_clean"
    return AgentScanResult(tuple(out), examinations)
