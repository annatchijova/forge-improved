import os


def read(base, user_path):
    return open(os.path.join(base, user_path)).read()
