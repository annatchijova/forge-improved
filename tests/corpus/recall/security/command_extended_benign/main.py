import shlex
import subprocess

COMMANDS = {"version": "ls -l"}


def run(name, command, choice):
    subprocess.run(["ls", name])
    subprocess.run(shlex.quote(command), shell=True)
    subprocess.run("ls -l", shell=True)
    return subprocess.run(COMMANDS[choice], shell=True)
