def load_artifact(raw):
    try:
        return raw["payload"]
    except KeyError as error:
        raise ValueError("artifact payload is required") from error
