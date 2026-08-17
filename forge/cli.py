from __future__ import annotations
import argparse
import json
from pathlib import Path
from forge.sealing import read_and_verify
from forge.tiered_report import MODES, render_tiered_report
from forge.reporting import render_sharded_dashboard
from forge.runtime import Runtime
from forge.models import ModelRouting
from forge.benchmark import run_benchmark
from forge.comparison import compare_runs
from forge.loop import run_loop
from forge.agent_independence import load_and_validate, write_validation_artifact, AgentIndependenceError
from forge.multi_agent import finalize_multi_agent_run

def main() -> int:
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        verify_parser = argparse.ArgumentParser(description="Verify a sealed FORGE finding manifest locally")
        verify_parser.add_argument("sealed", type=Path)
        verify_args = verify_parser.parse_args(sys.argv[2:])
        result = Runtime().verify_findings(verify_args.sealed)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("ok") else 1
    if len(sys.argv) > 1 and sys.argv[1] == "audit":
        audit_parser = argparse.ArgumentParser(description="Run the complete FORGE governance runtime")
        audit_parser.add_argument("repo", type=Path)
        audit_parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-run"))
        audit_parser.add_argument("--max-connected", type=int, default=100)
        audit_parser.add_argument("--orchestrator-model", help="model identifier for future model-backed orchestration")
        audit_parser.add_argument("--agent-model", action="append", default=[], metavar="AGENT=MODEL", help="agent model routing; repeatable")
        audit_parser.add_argument("--cronos-db", type=Path, help="optional SQLite CRONOS trace store")
        audit_parser.add_argument("--no-induction", action="store_true", help="disable target-code induction; keep static verification only")
        audit_parser.add_argument("--verify-syntax", action="store_true", help="verify lexically scanned source with each language's own parse-only tool (ruby -c, php -l, node --check); off by default because it shells out and availability would vary the result per machine")
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
        result = Runtime(max_connected=audit_args.max_connected, model_routing=routing, cronos_db=audit_args.cronos_db, induction=not audit_args.no_induction, syntax_validation=audit_args.verify_syntax).audit(audit_args.repo, audit_args.output_dir)
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
    if len(sys.argv) > 1 and sys.argv[1] == "audit-ref":
        ref_parser = argparse.ArgumentParser(description="Audit a committed Git ref without changing the repository")
        ref_parser.add_argument("repo", type=Path)
        ref_parser.add_argument("ref")
        ref_parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-ref-run"))
        ref_parser.add_argument("--max-connected", type=int, default=100)
        ref_parser.add_argument("--keep-checkout", action="store_true", help="keep the isolated extracted tree")
        ref_args = ref_parser.parse_args(sys.argv[2:])
        result = Runtime(max_connected=ref_args.max_connected).audit_ref(ref_args.repo, ref_args.ref, ref_args.output_dir, keep_checkout=ref_args.keep_checkout)
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
        if report_args.sealed.is_dir():
            if not (report_args.sealed / "shards.json").is_file():
                report_parser.error("report directory must contain shards.json")
            output = report_args.output or report_args.sealed / "forge-report-shards.html"
            print(render_sharded_dashboard(report_args.sealed, output))
            return 0
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
    if len(sys.argv) > 1 and sys.argv[1] == "compare":
        compare_parser = argparse.ArgumentParser(description="Compare two sealed FORGE audit runs")
        compare_parser.add_argument("previous", type=Path)
        compare_parser.add_argument("current", type=Path)
        compare_args = compare_parser.parse_args(sys.argv[2:])
        print(json.dumps(compare_runs(compare_args.previous, compare_args.current), indent=2, sort_keys=True))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "validate-agents":
        agent_parser = argparse.ArgumentParser(description="Validate independent external FORGE agent work products")
        agent_parser.add_argument("results_dir", type=Path)
        agent_parser.add_argument("--agent", action="append", required=True, help="required agent role; repeatable")
        agent_args = agent_parser.parse_args(sys.argv[2:])
        try:
            print(json.dumps(load_and_validate(agent_args.results_dir, agent_args.agent), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"status": "INDEPENDENCE_REJECTED", "error": str(exc)}, indent=2, sort_keys=True))
            return 2
    if len(sys.argv) > 1 and sys.argv[1] == "finalize-agents":
        agent_parser = argparse.ArgumentParser(description="Validate and close an external FORGE multi-agent run")
        agent_parser.add_argument("results_dir", type=Path)
        agent_parser.add_argument("--agent", action="append", required=True, help="required agent role; repeatable")
        agent_parser.add_argument("--output", type=Path, help="closing artifact path; defaults to results_dir/agent-independence.json")
        agent_args = agent_parser.parse_args(sys.argv[2:])
        try:
            print(json.dumps(write_validation_artifact(agent_args.results_dir, agent_args.agent, agent_args.output), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"status": "INDEPENDENCE_REJECTED", "error": str(exc)}, indent=2, sort_keys=True))
            return 2
    if len(sys.argv) > 1 and sys.argv[1] == "finalize-multi-agent":
        parser = argparse.ArgumentParser(description="Canonicalize and seal external plus native multi-agent findings")
        parser.add_argument("run_dir", type=Path)
        parser.add_argument("--agent", action="append", required=True)
        parser.add_argument("--external-findings", type=Path)
        parser.add_argument("--native-sealed", type=Path)
        parser.add_argument("--agent-results-dir", type=Path, help="directory containing one JSON work product per required agent")
        args = parser.parse_args(sys.argv[2:])
        try:
            print(json.dumps(finalize_multi_agent_run(args.run_dir, args.agent, args.external_findings, args.native_sealed, args.agent_results_dir), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"status": "CANONICALIZATION_REJECTED", "error": str(exc)}, indent=2, sort_keys=True))
            return 2
    if len(sys.argv) > 1 and sys.argv[1] == "compare-refs":
        refs_parser = argparse.ArgumentParser(description="Compare two committed Git refs through FORGE")
        refs_parser.add_argument("repo", type=Path)
        refs_parser.add_argument("base_ref")
        refs_parser.add_argument("head_ref")
        refs_parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-branch-run"))
        refs_parser.add_argument("--max-connected", type=int, default=100)
        refs_args = refs_parser.parse_args(sys.argv[2:])
        print(json.dumps(Runtime(max_connected=refs_args.max_connected).compare_refs(refs_args.repo, refs_args.base_ref, refs_args.head_ref, refs_args.output_dir), indent=2, sort_keys=True))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "loop":
        loop_parser = argparse.ArgumentParser(description="Run the bounded FORGE proposal/re-audit loop")
        loop_parser.add_argument("repo", type=Path)
        loop_parser.add_argument("ref")
        loop_parser.add_argument("-o", "--output-dir", type=Path, default=Path("forge-loop-run"))
        loop_parser.add_argument("--proposal-provider", choices=("deterministic", "human", "llm"), default="deterministic")
        loop_parser.add_argument("--patch", action="append", default=[], help="unified patch proposal; repeat per iteration")
        loop_parser.add_argument("--max-iterations", type=int, default=3)
        loop_parser.add_argument("--max-connected", type=int, default=100)
        loop_parser.add_argument("--test-command", nargs="+", help="test command to run in the temporary worktree")
        loop_args = loop_parser.parse_args(sys.argv[2:])
        print(json.dumps(run_loop(loop_args.repo, loop_args.ref, loop_args.output_dir, loop_args.proposal_provider,
                                  loop_args.patch, loop_args.max_iterations, loop_args.max_connected,
                                  loop_args.test_command), indent=2, sort_keys=True))
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
