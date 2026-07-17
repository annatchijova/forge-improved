def load_artifact(raw):
    try:
        return raw["payload"]
    except Exception:
        return None
