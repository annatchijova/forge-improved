from __future__ import annotations
import argparse
import json
from pathlib import Path
from forge.sealing import read_and_verify
from forge.tiered_report import MODES, render_tiered_report
from forge.runtime import Runtime
from forge.models import ModelRouting
from forge.benchmark import run_benchmark

def main() -> int:
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "audit":
        audit_parser = argparse.ArgumentParser(description="Run the complete FORGE governance runtime")
        audit_parser.add_argument("repo", type=Path)
        audit_parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-run"))
        audit_parser.add_argument("--max-connected", type=int, default=100)
        audit_parser.add_argument("--orchestrator-model", help="model identifier for future model-backed orchestration")
        audit_parser.add_argument("--agent-model", action="append", default=[], metavar="AGENT=MODEL", help="agent model routing; repeatable")
        audit_parser.add_argument("--cronos-db", type=Path, help="optional SQLite CRONOS trace store")
        audit_parser.add_argument("--summary", action="store_true", help="print compact run metrics instead of all finding records")
        audit_parser.add_argument("--quiet", action="store_true", help="print only the output directory after a successful run")
        audit_args = audit_parser.parse_args(sys.argv[2:])
        agent_models = {}
        for assignment in audit_args.agent_model:
            if "=" not in assignment:
                audit_parser.error("--agent-model must use AGENT=MODEL")
            agent, model = assignment.split("=", 1)
            if not agent or not model:
                audit_parser.error("--agent-model must use non-empty AGENT=MODEL")
            agent_models[agent] = model
        routing = ModelRouting(audit_args.orchestrator_model, agent_models)
        result = Runtime(max_connected=audit_args.max_connected, model_routing=routing, cronos_db=audit_args.cronos_db).audit(audit_args.repo, audit_args.output_dir)
        if audit_args.quiet:
            print(audit_args.output_dir)
        elif audit_args.summary:
            payload = result.to_dict()
            print(json.dumps({
                "repo": payload["repo"],
                "connected_alive": payload["connected_alive"],
                "findings": payload["findings"],
                "discarded": payload["discarded"],
                "coverage": payload["coverage"],
                "artifacts": payload["artifacts"],
            }, indent=2, sort_keys=True))
        else:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "preflight":
        preflight_parser = argparse.ArgumentParser(description="Run bounded FORGE discovery without auditing findings")
        preflight_parser.add_argument("repo", type=Path)
        preflight_parser.add_argument("--max-connected", type=int, default=100)
        preflight_args = preflight_parser.parse_args(sys.argv[2:])
        summary = Runtime(max_connected=preflight_args.max_connected).repository_summary(preflight_args.repo)
        connected = summary["summary"].get("CONNECTED_ALIVE", 0)
        print(json.dumps({
            **summary,
            "max_connected": preflight_args.max_connected,
            "scope_guard": {"ok": connected <= preflight_args.max_connected, "connected_alive": connected},
            "next_step": "audit" if connected <= preflight_args.max_connected else "choose an explicit higher --max-connected or an audit scope",
        }, indent=2, sort_keys=True))
        return 0 if connected <= preflight_args.max_connected else 2
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        report_parser = argparse.ArgumentParser(description="Render an existing sealed FORGE artifact")
        report_parser.add_argument("sealed", type=Path)
        report_parser.add_argument("--mode", choices=MODES, default="standard")
        report_parser.add_argument("-o", "--output", type=Path)
        report_args = report_parser.parse_args(sys.argv[2:])
        print(render_tiered_report(report_args.sealed, report_args.mode, report_args.output))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        benchmark_parser = argparse.ArgumentParser(description="Run bounded FORGE audits over a local corpus")
        benchmark_parser.add_argument("corpus", type=Path)
        benchmark_parser.add_argument("-o", "--output-dir", type=Path, default=Path("benchmark-run"))
        benchmark_parser.add_argument("--max-connected", type=int, default=100)
        benchmark_args = benchmark_parser.parse_args(sys.argv[2:])
        print(json.dumps(run_benchmark(benchmark_args.corpus, benchmark_args.output_dir, benchmark_args.max_connected), indent=2, sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description="FORGE module 1: stack detector and triage")
    parser.add_argument("repo", type=Path, nargs="?", help="repository root (required except with --verify-seal)")
    parser.add_argument("-o", "--output", type=Path, default=Path("triage-manifest.json"))
    parser.add_argument("--verify-seal", type=Path, help="verify a sealed verification manifest")
    args = parser.parse_args()
    if args.verify_seal:
        result = Runtime().verify_findings(args.verify_seal)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["ok"] else 1
    if args.repo is None:
        parser.error("repo is required unless --verify-seal is used")
    result = Runtime().audit(args.repo, args.output.parent)
    print(result.artifacts["triage"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
