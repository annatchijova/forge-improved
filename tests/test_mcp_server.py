import json
from pathlib import Path
from forge.mcp_server import audit_repository, get_audit_trace, get_coverage, get_findings, narrate_findings, verify_seal, review_patch, runtime_info
from forge.build_info import RUNTIME_FINGERPRINT

def put(root, name, text):
    p=root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text); return p

def test_mcp_runtime_info_reports_the_loaded_fingerprint():
    result = runtime_info()
    assert result["ok"] and result["runtime_fingerprint"] == RUNTIME_FINGERPRINT

def test_mcp_audit_result_carries_the_same_fingerprint_as_runtime_info(tmp_path):
    put(tmp_path, "main.py", "x = 1\n")
    result = audit_repository(str(tmp_path))
    metrics = json.loads(open(result["artifacts"]["metrics"]).read())
    assert metrics["reproducibility"]["runtime_fingerprint"] == runtime_info()["runtime_fingerprint"]

def test_mcp_audit_matches_direct_pipeline_shape(tmp_path):
    put(tmp_path, "main.py", "import security\n")
    put(tmp_path, "security.py", "password = 'secret'\n")
    result=audit_repository(str(tmp_path))
    assert result["ok"] and result["repo"] == str(tmp_path.resolve())
    assert {"coverage", "findings", "artifacts", "report_html_path"} <= result.keys()
    assert result["report_html_path"] == result["artifacts"]["report"]

def test_mcp_get_findings_filters_agent(tmp_path):
    put(tmp_path, "main.py", "import security\n")
    put(tmp_path, "security.py", "password = 'secret'\n")
    result=audit_repository(str(tmp_path))
    # Locate the run directory from the returned sealed artifact.
    run_dir=result["artifacts"]["sealed"].rsplit("/", 1)[0]
    findings=get_findings(run_dir, "security_auditor")
    assert findings and all(item["agent"] == "security_auditor" for item in findings)


def test_mcp_sharded_audit_returns_a_plan_and_parent_readers_work(tmp_path):
    put(tmp_path, "main.py", "import one\nimport two\n")
    put(tmp_path, "one.py", "password = 'secret'\n")
    put(tmp_path, "two.py", "def run(expr):\n    return eval(expr)\n")

    result = audit_repository(str(tmp_path), max_connected=1, output_dir=str(tmp_path.parent / "mcp-runs"))

    assert result["ok"] is True
    assert result["status"] == "PARTIAL_SHARDED"
    assert result["sharded"] is True
    assert "report_html_path" not in result
    assert Path(result["shard_plan_path"]).is_file()
    assert [item["index"] for item in result["shards"]] == [1, 2, 3]
    assert all("sealed" in item["artifacts"] for item in result["shards"])

    run_dir = str(Path(result["artifacts"]["shards"]).parent)
    coverage = get_coverage(run_dir)
    assert coverage["ok"] is True
    assert coverage["sharded"] is True
    assert coverage["coverage_aggregation"] == "REPOSITORY_WIDE_SNAPSHOT_WITH_UNIONED_LEXICAL_SCOPE"
    assert coverage["connected_alive_modules"] == 3
    assert [item["connected_alive_modules"] for item in coverage["detector_scope_by_shard"]] == [1, 1, 1]
    # A sharded run still publishes real counts. Requiring identical shard
    # snapshots used to null every one of them as soon as the repository held
    # any lexically-scanned source.
    assert coverage["files_analyzed"] is not None
    assert coverage["coverage_ratio"]["denominator"] == coverage["eligible_source_files"]

    findings = get_findings(run_dir)
    assert isinstance(findings, list)
    assert len(findings) == result["findings"]

    trace = get_audit_trace(run_dir)
    assert trace["ok"] is True
    assert any(event["kind"] == "run_completed" for event in trace["trace"]["events"])

def test_mcp_verify_seal_reports_tamper(tmp_path):
    put(tmp_path, "main.py", "def run(expr):\n    return eval(expr)\n")
    result=audit_repository(str(tmp_path)); sealed=json.loads(open(result["artifacts"]["sealed"]).read())
    sealed["chain"][0]["finding"]["description"] = "tampered"
    path=tmp_path/"tampered.json"; path.write_text(json.dumps(sealed))
    verified=verify_seal(str(path))
    assert verified["ok"] is False and any("hash mismatch" in issue for issue in verified["issues"])

def test_mcp_narration_is_read_only_and_non_evidentiary(tmp_path):
    put(tmp_path, "main.py", "password = 'secret'\n")
    result = audit_repository(str(tmp_path))
    response = narrate_findings(result["artifacts"]["sealed"])
    assert response["ok"] is True
    assert response["summary"]["seal_verified"] is True
    assert response["summary"]["evidence_authority"] is False
    assert response["summary"]["decision_authority"] is False

def test_mcp_audit_invalid_path_is_structured(tmp_path):
    result=audit_repository(str(tmp_path/"missing"))
    assert result["ok"] is False and result["error"]["code"] == "not_found"

def test_mcp_review_patch_result_is_json_serializable():
    diff = "@@ -1,2 +1,2 @@\n def run():\n-    return 1\n+    return 2\n"
    result = review_patch(diff, "run behavior change", "def run():\n    return 1\n", "def run():\n    return 2\n")
    # PatchReview.ratio is an exact Fraction; an MCP tool result must survive
    # a real json.dumps() round trip, not just asdict().
    encoded = json.dumps(result)
    assert "ratio" in result
    decoded = json.loads(encoded)
    assert decoded["ratio"] == result["ratio"]

def test_mcp_audit_default_ignores_audited_parent_permissions(tmp_path, monkeypatch):
    put(tmp_path, "main.py", "x = 1\n")
    original = Path.mkdir
    blocked = tmp_path.parent / ".forge-mcp-runs"
    def deny(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError("simulated parent permission failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "mkdir", deny)
    result = audit_repository(str(tmp_path))
    assert result["ok"] is True
    assert not Path(result["artifacts"]["report"]).is_relative_to(tmp_path)
