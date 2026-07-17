import yaml


def persist(handle, payload):
    yaml.dump(payload, handle)
