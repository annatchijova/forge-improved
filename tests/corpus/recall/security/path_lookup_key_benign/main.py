config = {}


def read(user_path):
    return open(config.get(user_path))


def indexed(user_path):
    return open(config[user_path])
