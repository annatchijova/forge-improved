import json


def persist(handle, payload):
    handle.write(json.dumps(payload))
