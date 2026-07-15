"""Sequential, bounded orchestration of the FORGE evidence pipeline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from forge.detector.stack import triage, write_manifest
from forge.hypotheses import generate_hypotheses, write_hypotheses_manifest
from forge.report import render_report
from forge.sealing import write_sealed_manifest
from forge.verification import verify_hypotheses, write_verification_manifest


def run_pipeline(repo: str | Path, output_dir: str | Path, max_connected: int = 100) -> dict[str, Any]:
    """Run specialized agents sequentially and refuse broad downstream scope.

    The guard runs immediately after ``triage()`` returns. It prevents the
    remaining agents from running, but cannot make triage itself cheaper.
    """
    root = Path(repo).resolve()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    triage_manifest = triage(root)
    connected = triage_manifest.summary.get(
        "CONNECTED_ALIVE",
        sum(m.module_class.value == "CONNECTED_ALIVE" for m in triage_manifest.modules),
    )
    if connected > max_connected:
        raise ValueError(f"scope guard: {connected} CONNECTED_ALIVE modules exceeds max_connected={max_connected}")
    triage_path = out / "triage-manifest.json"
    hypotheses_path = out / "hypotheses-manifest.json"
    verification_path = out / "verification-manifest.json"
    sealed_path = out / "verification-manifest.sealed.json"
    report_path = out / "forge-report.html"
    write_manifest(triage_manifest, triage_path)
    hypotheses = generate_hypotheses(triage_manifest)
    write_hypotheses_manifest(hypotheses, hypotheses_path)
    verification = verify_hypotheses(hypotheses)
    write_verification_manifest(verification, verification_path)
    write_sealed_manifest(verification, sealed_path)
    render_report(triage_path, hypotheses_path, sealed_path, report_path)
    return {
        "repo": str(root),
        "output_dir": str(out.resolve()),
        "connected_alive": connected,
        "findings": len(verification.findings),
        "discarded": len(verification.discarded),
        "artifacts": {name: str(path) for name, path in {
            "triage": triage_path, "hypotheses": hypotheses_path,
            "verification": verification_path, "sealed": sealed_path,
            "report": report_path,
        }.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded FORGE agents in sequence")
    parser.add_argument("repo", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-run"))
    parser.add_argument("--max-connected", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(run_pipeline(args.repo, args.output_dir, args.max_connected), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
