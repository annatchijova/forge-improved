import hashlib

def canonical_json(payload):
    return repr(sorted(payload.items()))

def seal(payload):
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
