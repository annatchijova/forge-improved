import yaml


def load(text):
    return yaml.unsafe_load(text)
