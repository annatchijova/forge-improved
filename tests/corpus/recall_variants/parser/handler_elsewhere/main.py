import json


def parse(raw):
    return json.loads(raw)


def boundary(raw):
    try:
        return parse(raw)
    except json.JSONDecodeError:
        raise ValueError("invalid")
