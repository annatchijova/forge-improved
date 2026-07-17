import os


def configure(config):
    config["password"] = os.getenv("PASSWORD")
    self.api_key = ""
    self.token = "changeme"
    return {"password": "", "api_key": "your-key-here"}
