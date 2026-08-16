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
    assert all((tmp_path / "out" / "shards" / f"shard-{index:04d}" / "forge-report-standard.html").exists() for index in range(1, 4))


def test_sharded_result_does_not_claim_parent_seal(tmp_path):
    (tmp_path / "main.py").write_text("import one\nimport two\n")
    (tmp_path / "one.py").write_text("x = 1\n")
    (tmp_path / "two.py").write_text("x = 2\n")
    result = Runtime(max_connected=1).audit(tmp_path, tmp_path / "out")
    payload = result.to_dict()
    assert payload["status"] == "PARTIAL_SHARDED"
    assert "sealed" not in payload["artifacts"]


def test_sharded_coverage_unions_lexical_scope_instead_of_abstaining(tmp_path):
    # A lexical file is scanned only by the shard whose scope contains it and
    # is out of scope in every other shard. Requiring identical shard snapshots
    # therefore guaranteed a mismatch on any repository holding lexical source,
    # and nulled every parent count -- files_analyzed, the ratio, and the whole
    # language matrix. The shard-sensitive half is unioned now, not compared.
    (tmp_path / "main.py").write_text("import one\nimport two\n")
    (tmp_path / "one.py").write_text("x = 1\n")
    (tmp_path / "two.py").write_text("x = 2\n")
    (tmp_path / "index.ts").write_text("import { helper } from './helper';\n")
    (tmp_path / "helper.ts").write_text("export const helper = () => 1;\n")
    (tmp_path / "main.go").write_text("package main\n\nfunc main() {}\n")

    result = Runtime(max_connected=2).audit(tmp_path, tmp_path / "out")
    coverage = result.coverage
    assert result.status == "PARTIAL_SHARDED"
    assert coverage["coverage_aggregation"] == "REPOSITORY_WIDE_SNAPSHOT_WITH_UNIONED_LEXICAL_SCOPE"

    # Every eligible source file is accounted for exactly once, and the lexical
    # languages report the depth that produced their counts.
    assert coverage["files_analyzed"] == coverage["eligible_source_files"] == 6
    assert coverage["language_coverage"]["Python"] == {"analyzed": 3, "abstained": 0, "depth": "ast"}
    assert coverage["language_coverage"]["JavaScript/TypeScript"] == {
        "analyzed": 2, "abstained": 0, "depth": "lexical",
    }
    assert coverage["language_coverage"]["Go"] == {"analyzed": 1, "abstained": 0, "depth": "lexical"}


def test_sharded_coverage_still_abstains_when_shards_saw_different_trees(tmp_path):
    # Unioning the shard-sensitive half must not weaken the real anomaly check:
    # if shards disagree on repository-wide parse facts they did not audit the
    # same tree, and no parent count may be published.
    from forge.runtime import _repository_wide_agreement

    base = {
        "files_discovered": 10,
        "eligible_source_files": 4,
        "skipped_reasons": {"excluded_by_policy": ["a.py"], "out_of_detector_scope": ["x.ts"]},
        "files_analyzed": 3,
        "language_coverage": {"Python": {"analyzed": 3}},
    }
    differing_scope = {**base, "files_analyzed": 4, "language_coverage": {"Python": {"analyzed": 4}},
                       "skipped_reasons": {"excluded_by_policy": ["a.py"], "out_of_detector_scope": []}}
    differing_tree = {**base, "files_discovered": 11}

    assert _repository_wide_agreement([base, differing_scope]), "scope differences are expected"
    assert not _repository_wide_agreement([base, differing_tree]), "tree differences are an anomaly"


def test_every_shard_seals_the_same_repository_snapshot(tmp_path):
    # Shards run sequentially, so with the output directory inside the audited
    # repository -- what `forge audit . -o forge-run` produces -- each shard
    # used to discover the artifacts its predecessors had just written. Shards
    # of one audit then sealed different repository_snapshot_sha256 values for
    # the same tree, and disagreed on how many files it held.
    (tmp_path / "main.py").write_text("import one\nimport two\n")
    (tmp_path / "one.py").write_text("x = 1\n")
    (tmp_path / "two.py").write_text("x = 2\n")
    (tmp_path / "index.ts").write_text("import { helper } from './helper';\n")
    (tmp_path / "helper.ts").write_text("export const helper = () => 1;\n")

    result = Runtime(max_connected=2).audit(tmp_path, tmp_path / "out")
    assert result.status == "PARTIAL_SHARDED"

    snapshots, discovered = set(), set()
    for shard in sorted((tmp_path / "out" / "shards").iterdir()):
        manifest = json.loads((shard / "verification-manifest.json").read_text())
        snapshots.add(manifest["repository_snapshot_sha256"])
        discovered.add(json.loads((shard / "coverage-report.json").read_text())["files_discovered"])
    assert len(snapshots) == 1, f"shards attested different trees: {snapshots}"
    assert len(discovered) == 1, f"shards counted different file totals: {discovered}"

    # And the parent still publishes real counts rather than abstaining.
    assert result.coverage["coverage_aggregation"] == "REPOSITORY_WIDE_SNAPSHOT_WITH_UNIONED_LEXICAL_SCOPE"
    assert result.coverage["files_analyzed"] == 5
