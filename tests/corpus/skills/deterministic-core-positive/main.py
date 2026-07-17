import hashlib
import json

def seal(payload):
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()
