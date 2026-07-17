"""Process-local provenance attestation for FORGE-generated manifests."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Any

from forge.canonical import canonical_json

_EPHEMERAL_KEY = secrets.token_bytes(32)


def _resolve_key() -> tuple[bytes, str]:
    """Return the configured cross-process key or this process's fallback key."""
    configured = os.environ.get("FORGE_ATTESTATION_KEY")
    if configured:
        return configured.encode("utf-8"), "PERSISTENT"
    return _EPHEMERAL_KEY, "EPHEMERAL"


def attestation_mode() -> str:
    """Expose whether an attestation can be verified outside this process."""
    return _resolve_key()[1]


def _payload(manifest: dict[str, Any]) -> bytes:
    unsigned = dict(manifest)
    unsigned.pop("source_attestation", None)
    return canonical_json(unsigned).encode("utf-8")


def attest_manifest(manifest: dict[str, Any]) -> str:
    """Create an in-process token proving Runtime generated this manifest."""
    key, _ = _resolve_key()
    return hmac.new(key, _payload(manifest), hashlib.sha256).hexdigest()


def verify_manifest_attestation(manifest: dict[str, Any]) -> bool:
    token = manifest.get("source_attestation")
    if not isinstance(token, str) or not token:
        return False
    expected = attest_manifest(manifest)
    return hmac.compare_digest(token, expected)
