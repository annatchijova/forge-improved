import subprocess


def run(command):
    shell = True
    return subprocess.run(command, shell=shell)
