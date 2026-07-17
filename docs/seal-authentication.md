# Authenticated FORGE seals

FORGE always creates a deterministic SHA-256 finding chain. That chain detects
local modification of a sealed finding record, but by itself it is **not** an
external identity guarantee: someone who can replace the complete artifact can
also construct a new internally consistent chain.

Set `FORGE_SEAL_HMAC_KEY` to add an HMAC-SHA256 authenticator over the complete
sealed artifact. This covers the findings, manifest metadata, trace binding,
and limitations without writing the key into any report or JSON artifact.

## Local use

Generate a long random secret once and keep it in your local secret manager or
an environment file that is excluded from version control:

```bash
export FORGE_SEAL_HMAC_KEY="$(openssl rand -hex 32)"
```

Run the audit and verification/report commands in environments that have the
same secret:

```bash
forge audit /path/to/repository --output forge-run
forge report forge-run/verification-manifest.sealed.json --mode standard
```

When the key is present during both sealing and verification, reports identify
the artifact as **“Sealed evidence — authenticated.”**

## Verification behavior

| Artifact | Verification environment | Result |
| --- | --- | --- |
| Hash-chain only | No key required | Internally consistent chain; not externally authenticated. |
| HMAC-authenticated | Same key available | Authenticated artifact. |
| HMAC-authenticated | Key absent or wrong | Verification fails closed; findings are withheld from HTML reports. |

## Key handling rules

- Never commit the key, place it in an audit artifact, or paste it into a demo
  prompt, report, issue, or chat transcript.
- Give the signing process and independent verifier the secret through their
  environment or a secret manager. An MCP server must be restarted after its
  environment changes.
- Preserve the key securely for as long as old artifacts must remain
  independently verifiable. Rotating it without retaining the old value makes
  previously authenticated artifacts unverifiable.
- HMAC authenticates possession of the shared secret; it does not prove that
  the findings are correct, complete, or fit for a particular scope.

For a third-party, public-verification workflow, use a signature scheme with a
separate private signing key and public verification key. The current HMAC mode
is intentionally a pragmatic local/MCP protection against complete artifact
replacement.

## Runtime assembly attestation

`FORGE_ATTESTATION_KEY` is distinct from `FORGE_SEAL_HMAC_KEY`. It creates a
`source_attestation` over the assembled sealed artifact and lets a later process
with the same key report `attestation_status: VERIFIED` from `verify_sealed()`.
The key is never serialized.

```bash
export FORGE_ATTESTATION_KEY="$(openssl rand -hex 32)"
```

Without that setting FORGE uses one process-local fallback key and reports
`EPHEMERAL_UNVERIFIABLE`, not a false cross-process verification. A missing
persistent key is reported as `KEY_UNAVAILABLE`; a present but invalid tag is
`FAILED` and makes seal verification fail.

Assembly attestation is not analytical provenance. In a canonical multi-agent
artifact, native findings are labeled `FORGE_NATIVE`; Codex/external findings
are `UNATTESTED` unless a human operator explicitly signs the external findings
envelope with `FORGE_ATTESTATION_KEY`. FORGE never auto-attests external
content. An `UNATTESTED` external layer yields
`ABSTAIN_UNATTESTED_EXTERNAL` even when the canonical artifact's own assembly
attestation verifies.
