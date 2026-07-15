from __future__ import annotations
import argparse
from pathlib import Path
from forge.detector.stack import triage, write_manifest

def main() -> int:
    parser = argparse.ArgumentParser(description="FORGE module 1: stack detector and triage")
    parser.add_argument("repo", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("triage-manifest.json"))
    args = parser.parse_args()
    write_manifest(triage(args.repo), args.output)
    print(args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
