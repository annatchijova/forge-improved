from __future__ import annotations
import argparse
from pathlib import Path
from forge.detector.stack import triage, write_manifest
from forge.hypotheses import generate_hypotheses, write_hypotheses_manifest

def main() -> int:
    parser = argparse.ArgumentParser(description="FORGE module 1: stack detector and triage")
    parser.add_argument("repo", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("triage-manifest.json"))
    parser.add_argument("--hypotheses", type=Path, help="also write the module 2 hypotheses manifest")
    args = parser.parse_args()
    manifest = triage(args.repo)
    write_manifest(manifest, args.output)
    if args.hypotheses:
        write_hypotheses_manifest(generate_hypotheses(manifest), args.hypotheses)
    print(args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
