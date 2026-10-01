import os
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    jwt_secret: str
    environment: str = "development"
    public_url: str = "http://localhost:8000"
    mail_dir: str = ".dev-mail"
    github_client_id: str = ""
    github_client_secret: str = ""
    access_seconds: int = 600
    refresh_seconds: int = 604800
    session_seconds: int = 2592000
    auth_limit: str = "20/minute"
    account_limit: str = "10/minute"

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            database_url=os.environ.get("DATABASE_URL", ""),
            redis_url=os.environ.get("REDIS_URL", ""),
            jwt_secret=os.environ.get("JWT_SECRET", ""),
            environment=os.environ.get("APP_ENV", "development"),
            public_url=os.environ.get("PUBLIC_URL", "http://localhost:8000"),
            mail_dir=os.environ.get("MAIL_DIR", ".dev-mail"),
            github_client_id=os.environ.get("GITHUB_CLIENT_ID", ""),
            github_client_secret=os.environ.get("GITHUB_CLIENT_SECRET", ""),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL must use postgresql+psycopg")
        if not self.redis_url.startswith(("redis://", "rediss://")):
            raise ValueError("REDIS_URL must use Redis")
        if len(self.jwt_secret.encode()) < 32:
            raise ValueError("JWT_SECRET must contain at least 32 bytes")
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("Invalid APP_ENV")
        origin = urlparse(self.public_url)
        if origin.scheme not in {"http", "https"} or not origin.hostname:
            raise ValueError("Invalid PUBLIC_URL")
        if origin.port is not None and not 1 <= origin.port <= 65535:
            raise ValueError("Invalid PUBLIC_URL port")
        if origin.query or origin.fragment or origin.username or origin.path not in {"", "/"}:
            raise ValueError("PUBLIC_URL must be an origin")
        if self.environment == "production":
            if origin.scheme != "https":
                raise ValueError("Production requires HTTPS")
            raise ValueError("V1 development email adapter is not enabled for production")
        if not 0 < self.access_seconds <= self.refresh_seconds <= self.session_seconds:
            raise ValueError("Invalid token lifetimes")
        if bool(self.github_client_id) != bool(self.github_client_secret):
            raise ValueError("Both GitHub credentials are required")
