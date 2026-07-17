import subprocess


def build_command(user_name):
    return subprocess.run("echo " + user_name, shell=True, check=False)
