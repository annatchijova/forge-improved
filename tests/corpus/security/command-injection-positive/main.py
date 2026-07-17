import subprocess

@app.post("/convert")
def convert(name):
    return subprocess.run("convert --name=" + name, shell=True, check=True)
