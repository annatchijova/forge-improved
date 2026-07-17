import json


def parse(raw):
    try:
        return json.loads(raw)
    except KeyError:
        raise ValueError("invalid")
