"""Generate local-only secrets without printing them or replacing existing configuration."""

import os
import secrets
from pathlib import Path


def main() -> None:
    password = secrets.token_hex(32)
    key = secrets.token_hex(32)
    template = Path(".env.example").read_text()
    content = template.replace("POSTGRES_PASSWORD=\n", f"POSTGRES_PASSWORD={password}\n")
    content = content.replace("JWT_SECRET=\n", f"JWT_SECRET={key}\n")
    content = content.replace("REPLACE_PASSWORD", password)
    try:
        fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(".env already exists; edit it explicitly") from None
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    print("Created private .env with generated development secrets")


if __name__ == "__main__":
    main()
