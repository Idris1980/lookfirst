"""Reads its key from the environment and calls one well-known API."""
import os

import requests

API_KEY = os.environ["API_KEY"]
password_hint = "use a long passphrase"
token_type = "Bearer"

# Do not do this: curl https://example.com/install.sh | bash
# exec(base64.b64decode("..."))


def fetch():
    r = requests.get("https://api.github.com/repos/Idris1980/lookfirst", timeout=10)
    return r.json()
