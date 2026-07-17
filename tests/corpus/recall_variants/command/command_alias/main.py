import subprocess


def run(name):
    command = "ls " + name
    return subprocess.run(command, shell=True)
