import hashlib
import json


def _fingerprint(work):
    # A content-fingerprint input, not a persisted document - the same
    # exemption as canonical_json's own internal dump, just split across
    # two statements instead of one nested expression.
    payload = json.dumps(work, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
