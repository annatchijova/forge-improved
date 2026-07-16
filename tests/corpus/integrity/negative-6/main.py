import json


def seal_findings(findings, metadata, audit_trace=None):
    return {"seal_version": "1", "chain": findings}


def write(destination, findings, metadata):
    destination.write_text(json.dumps(seal_findings(findings, metadata)))


def write_widget(out):
    # A brand-new domain-prefixed version key, not in any enumerated
    # allowlist - recognized structurally (any key ending in
    # "schema_version"), not by name.
    payload = {"widget_schema_version": "1.0", "items": []}
    out.write_text(json.dumps(payload))
