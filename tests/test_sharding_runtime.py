import json

from forge import Runtime


def test_runtime_shards_when_connected_scope_exceeds_limit(tmp_path):
    imports = "".join(f"import mod{i}\n" for i in range(5))
    (tmp_path / "main.py").write_text(imports)
    for index in range(5):
        (tmp_path / f"mod{index}.py").write_text(f"VALUE = {index}\n")

    result = Runtime(max_connected=2).audit(tmp_path, tmp_path / "out")
    assert result.status == "PARTIAL_SHARDED"
    assert result.connected_alive == 6
    plan = json.loads((tmp_path / "out" / "shards.json").read_text())
    assert plan["status"] == "PARTIAL_SHARDED"
    assert len(plan["shards"]) == 3
    assert all(item["status"] == "COMPLETE" for item in plan["shards"])
    assert all((tmp_path / "out" / "shards" / f"shard-{index:04d}" / "verification-manifest.sealed.json").exists() for index in range(1, 4))


def test_sharded_result_does_not_claim_parent_seal(tmp_path):
    (tmp_path / "main.py").write_text("import one\nimport two\n")
    (tmp_path / "one.py").write_text("x = 1\n")
    (tmp_path / "two.py").write_text("x = 2\n")
    result = Runtime(max_connected=1).audit(tmp_path, tmp_path / "out")
    payload = result.to_dict()
    assert payload["status"] == "PARTIAL_SHARDED"
    assert "sealed" not in payload["artifacts"]
