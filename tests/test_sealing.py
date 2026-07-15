import copy

from forge.models import Evidence, Finding, VerificationManifest
from forge.sealing import seal_manifest, verify_sealed


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
