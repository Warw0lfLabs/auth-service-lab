import json
import os
import secrets
from pathlib import Path


class DevelopmentEmail:
    """Private local files, never application logs or API responses."""

    def __init__(self, directory: str) -> None:
        self.directory = Path(directory)

    def send(self, recipient: str, purpose: str, token: str) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        path = self.directory / f"{secrets.token_hex(16)}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"to": recipient, "purpose": purpose, "token": token}, stream)
