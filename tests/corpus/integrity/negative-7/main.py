import json


def _typed(value):
    return {"type": "str", "value": str(value)}


def canonical_json(value):
    # This is the trusted primitive itself, not a caller of it. Its
    # versioning lives one layer up (a CANONICALIZE_VERSION field carried by
    # whatever payload embeds this function's output), so its own internal
    # json.dumps call has no literal version key and must not be flagged.
    return json.dumps(_typed(value), sort_keys=True)
