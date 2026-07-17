import copy
import json
import os
import subprocess
import sys
from pathlib import Path

from forge.models import Evidence, Finding, VerificationManifest
from forge.sealing import seal_manifest, verify_sealed, write_findings_jsonl


def _manifest():
    finding = lambda n: Finding("INFERRED", "PLAUSIBLE HYPOTHESIS", f"m{n}.py", f"finding {n}", (Evidence("source", f"m{n}.py:1", "x"),), "reason")
    return VerificationManifest("1.0", "0.1.0", "1.0", ".", 0, tuple(finding(n) for n in range(4)), (), ())


def test_chain_passes_and_catches_local_tamper_but_not_full_cascade_forgery():
    sealed = seal_manifest(_manifest())
    assert verify_sealed(sealed)["ok"]
    tampered = copy.deepcopy(sealed)
    tampered["chain"][1]["finding"]["description"] = "altered"
    result = verify_sealed(tampered)
    assert not result["ok"] and "entry 1: hash mismatch" in result["issues"]
    reordered = copy.deepcopy(sealed)
    reordered["chain"][1], reordered["chain"][2] = reordered["chain"][2], reordered["chain"][1]
    assert not verify_sealed(reordered)["ok"]
    forged = copy.deepcopy(tampered)
    previous = forged["chain"][0]["prev_hash"]
    from forge.sealing import _digest
    for entry in forged["chain"]:
        entry["prev_hash"] = previous
        entry["hash"] = _digest({"index": entry["index"], "finding": entry["finding"]}, previous)
        previous = entry["hash"]
    assert verify_sealed(forged)["ok"]


def test_truncation_with_edited_reported_length_is_expected_limitation():
    sealed = seal_manifest(_manifest())
    truncated = copy.deepcopy(sealed)
    truncated["chain"] = truncated["chain"][:2]
    truncated["reported_chain_length"] = 2
    # This deliberately passes: the length is a freely editable convenience field.
    assert verify_sealed(truncated)["ok"]


def test_optional_hmac_authentication_covers_the_complete_artifact(monkeypatch):
    monkeypatch.setenv("FORGE_SEAL_HMAC_KEY", "test-only-external-key")
    sealed = seal_manifest(_manifest())
    assert sealed["authentication"]["scheme"] == "HMAC-SHA256"
    assert verify_sealed(sealed)["ok"]
    assert verify_sealed(sealed)["authentication_status"] == "VERIFIED"

    sealed["manifest"]["discarded"] = [{"reason": "attacker-controlled"}]
    verified = verify_sealed(sealed)
    assert verified["ok"] is False
    assert "authentication tag mismatch" in verified["issues"]


def test_source_attestation_is_visible_without_turning_ephemeral_seals_into_false_failures(monkeypatch):
    monkeypatch.delenv("FORGE_ATTESTATION_KEY", raising=False)
    sealed = seal_manifest(_manifest())
    verified = verify_sealed(sealed)
    assert verified["ok"] is True
    assert verified["attestation_status"] == "EPHEMERAL_UNVERIFIABLE"
    assert verified["attestation_ok"] is None

    absent = copy.deepcopy(sealed)
    absent.pop("source_attestation")
    absent.pop("source_attestation_mode")
    absent_verified = verify_sealed(absent)
    assert absent_verified["ok"] is True
    assert absent_verified["attestation_status"] == "NOT_PRESENT"


def test_persistent_source_attestation_verifies_cross_process_and_fails_when_tampered(monkeypatch):
    key = "test-only-persistent-attestation-key"
    monkeypatch.setenv("FORGE_ATTESTATION_KEY", key)
    script = """\
import json
from forge.models import Evidence, Finding, VerificationManifest
from forge.sealing import seal_manifest
finding = Finding("INFERRED", "PLAUSIBLE HYPOTHESIS", "main.py", "finding", (Evidence("source", "main.py:1", "x"),), "reason")
print(json.dumps(seal_manifest(VerificationManifest("1.0", "0.1.0", "1.0", ".", 0, (finding,), (), ()))))
"""
    environment = dict(os.environ)
    environment["FORGE_ATTESTATION_KEY"] = key
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        check=True,
        text=True,
    )
    sealed = json.loads(completed.stdout)
    verified = verify_sealed(sealed)
    assert verified["ok"] is True
    assert verified["attestation_status"] == "VERIFIED"
    assert verified["attestation_ok"] is True
    assert seal_manifest(_manifest())["source_attestation"] == seal_manifest(_manifest())["source_attestation"]

    monkeypatch.delenv("FORGE_ATTESTATION_KEY")
    unavailable = verify_sealed(sealed)
    assert unavailable["ok"] is True
    assert unavailable["attestation_status"] == "KEY_UNAVAILABLE"
    monkeypatch.setenv("FORGE_ATTESTATION_KEY", key)

    tampered = copy.deepcopy(sealed)
    tampered["source_attestation"] = "forged"
    failed = verify_sealed(tampered)
    assert failed["ok"] is False
    assert failed["attestation_status"] == "FAILED"
    assert "source attestation mismatch" in failed["issues"]


def test_signed_artifact_fails_closed_when_authentication_key_is_unavailable(monkeypatch):
    monkeypatch.setenv("FORGE_SEAL_HMAC_KEY", "test-only-external-key")
    sealed = seal_manifest(_manifest())
    monkeypatch.delenv("FORGE_SEAL_HMAC_KEY")
    verified = verify_sealed(sealed)
    assert verified["ok"] is False
    assert verified["authentication_status"] == "KEY_UNAVAILABLE"


def test_finding_chain_hashes_are_reproducible_even_with_an_audit_trace():
    # A run-specific audit_trace (random run_id, wall-clock timestamps) must
    # not leak into the per-finding chain hash: two honest runs over
    # identical findings must produce identical chain hashes, or the seal's
    # bit-for-bit reproducibility claim (deterministic-core) is false.
    trace_a = {"trace_version": "1", "run_id": "11111111-1111-1111-1111-111111111111", "started_at": "2026-01-01T00:00:00Z", "events": []}
    trace_b = {"trace_version": "1", "run_id": "22222222-2222-2222-2222-222222222222", "started_at": "2026-01-01T00:00:01Z", "events": []}
    sealed_a = seal_manifest(_manifest(), trace_a)
    sealed_b = seal_manifest(_manifest(), trace_b)
    assert [entry["hash"] for entry in sealed_a["chain"]] == [entry["hash"] for entry in sealed_b["chain"]], (
        "chain hashes differ between two runs with identical findings but different "
        "audit traces - the trace (run_id/timestamp) is leaking into the finding hash"
    )
    assert verify_sealed(sealed_a)["ok"] and verify_sealed(sealed_b)["ok"]


def test_findings_jsonl_has_one_versioned_self_describing_record_per_finding(tmp_path):
    sealed = seal_manifest(_manifest())
    destination = tmp_path / "findings.jsonl"
    write_findings_jsonl(sealed, destination)
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(sealed["chain"])
    for line, entry in zip(lines, sealed["chain"]):
        record = json.loads(line)
        assert record["findings_jsonl_schema_version"] == "1.0"
        assert record["index"] == entry["index"]
        assert record["hash"] == entry["hash"]
        assert record["finding"] == json.loads(json.dumps(entry["finding"], sort_keys=True))


def test_findings_jsonl_is_empty_but_valid_for_a_clean_manifest(tmp_path):
    sealed = seal_manifest(VerificationManifest("1.0", "0.1.0", "1.0", ".", 0, (), (), ()))
    destination = tmp_path / "findings.jsonl"
    write_findings_jsonl(sealed, destination)
    assert destination.read_text(encoding="utf-8") == ""
