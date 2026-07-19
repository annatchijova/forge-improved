"""Stage 1: deterministic weakness signatures from sealed historical runs."""
from __future__ import annotations
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from forge.io import load_json
from forge.sealing import verify_sealed
from forge.severity import finding_family

LEDGER_AGENT = "ledger"

@dataclass(frozen=True)
class FailureInstance:
    run: str; module_path: str; agent: str; family: str; check: str; mechanism: str
@dataclass(frozen=True)
class WeaknessCluster:
    signature: tuple[str, str, str]; frequency: int; examples: tuple[FailureInstance, ...]; agent: str; family: str
@dataclass(frozen=True)
class WeaknessBundle:
    clusters: tuple[WeaknessCluster, ...]

def _read(run):
    if isinstance(run, (str, Path)):
        data, label = load_json(run, f"mined run {run}"), str(run)
    elif isinstance(run, dict):
        data, label = run, "memory"
    else:
        raise ValueError("mined run must be a sealed FORGE artifact or its decoded object")
    verification = verify_sealed(data)
    if not verification.get("ok"):
        raise ValueError(f"cannot mine unverified sealed run {label}: {verification.get('issues', [])}")
    if not (
        verification.get("authentication_status") == "VERIFIED"
        or verification.get("attestation_status") == "VERIFIED"
    ):
        raise ValueError(
            f"cannot mine unauthenticated sealed run {label}: "
            "a verified HMAC seal or persistent source attestation is required"
        )
    return data, label

def mine(runs) -> WeaknessBundle:
    groups = defaultdict(list)
    for run in runs:
        data, label = _read(run); manifest = data.get("manifest", data)
        for item in manifest.get("discarded", []):
            check=item.get("reason", "unknown discard check"); agent=item.get("agent", "bug_investigator"); family=item.get("family", item.get("pattern_family", "unknown")); mechanism=item.get("mechanism", item.get("description", check))
            groups[(check, agent, mechanism)].append(FailureInstance(label, item.get("module_path", "unknown"), agent, family, check, mechanism))
        findings = list(manifest.get("findings", []))
        findings.extend(entry.get("finding", {}) for entry in data.get("chain", []))
        for item in findings:
            agent=item.get("agent", "bug_investigator"); check=item.get("reasoning", "finding survived verification"); family=item.get("family", item.get("pattern_family", "unknown")); mechanism=item.get("mechanism", item.get("description", "unknown mechanism"))
            groups[(check, agent, mechanism)].append(FailureInstance(label, item.get("module_path", "unknown"), agent, family, check, mechanism))
    clusters=[WeaknessCluster(sig, len(items), tuple(items[:5]), items[0].agent, items[0].family) for sig, items in groups.items()]
    return WeaknessBundle(tuple(sorted(clusters, key=lambda c: (-c.frequency, c.signature))))


def _ledger_rows(path: str | Path) -> list[dict[str, str]]:
    """Parse the '| ID | Source run | Trigger | Root cause | ... |' table.

    Only the ledger's own contract columns are read; an unrelated table
    elsewhere in the document (different header) is skipped rather than
    misparsed.
    """
    header = None
    rows: list[dict[str, str]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if header is None:
            if cells[:2] == ["ID", "Source run"]:
                header = cells
            continue
        if set(cells[0]) <= {"-", ":"}:
            continue
        if len(cells) != len(header):
            continue
        rows.append(dict(zip(header, cells)))
    return rows


def mine_ledger(path: str | Path) -> WeaknessBundle:
    """Mine the false-positive ledger as a source of known weakness signatures.

    Each row is a human-adjudicated false positive with its root cause and
    triggering pattern already recorded (see docs/false-positive-ledger.md's
    entry contract). Mining it lets the harness recognise when a *new* run's
    discarded hypotheses or findings match a cause the ledger already closed
    once, instead of only learning from runs the harness has seen before.
    """
    groups = defaultdict(list)
    for row in _ledger_rows(path):
        entry_id = row.get("ID", "unknown")
        run_label = row.get("Source run", "ledger")
        trigger = row.get("Trigger", "")
        root_cause = row.get("Root cause", "unknown root cause")
        family = finding_family(f"{trigger} {root_cause}")
        groups[(root_cause, LEDGER_AGENT, trigger)].append(
            FailureInstance(run_label, entry_id, LEDGER_AGENT, family, root_cause, trigger)
        )
    clusters = [
        WeaknessCluster(sig, len(items), tuple(items[:5]), items[0].agent, items[0].family)
        for sig, items in groups.items()
    ]
    return WeaknessBundle(tuple(sorted(clusters, key=lambda c: (-c.frequency, c.signature))))


def combine(*bundles: WeaknessBundle) -> WeaknessBundle:
    """Merge clusters from multiple sources (sealed runs, the ledger, ...).

    Clusters sharing the exact same signature accumulate frequency and
    examples instead of appearing as separate, artificially small clusters.
    """
    groups: dict[tuple[str, str, str], list] = defaultdict(list)
    for bundle in bundles:
        for cluster in bundle.clusters:
            groups[cluster.signature].extend(cluster.examples)
    clusters = [
        WeaknessCluster(sig, len(items), tuple(items[:5]), items[0].agent, items[0].family)
        for sig, items in groups.items() if items
    ]
    return WeaknessBundle(tuple(sorted(clusters, key=lambda c: (-c.frequency, c.signature))))
