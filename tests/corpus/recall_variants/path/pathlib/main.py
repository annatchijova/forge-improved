from pathlib import Path


def read(user_path):
    return Path(user_path).read_text()
