from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from auth_service.errors import Problem


class Profile(BaseModel):
    model_config = ConfigDict(strict=True)
    id: int = Field(gt=0)
    login: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9-]+$")
    name: str | None = None
    avatar_url: str
    html_url: str


class GitHubClient:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self.transport = transport

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            with httpx.Client(
                timeout=httpx.Timeout(5, connect=2),
                transport=self.transport,
                follow_redirects=False,
            ) as client:
                with client.stream(method, url, **kwargs) as response:
                    if response.status_code in {403, 429}:
                        raise Problem(503, "upstream_limited", "GitHub is unavailable")
                    if response.status_code >= 400:
                        raise Problem(502, "upstream_error", "GitHub request failed")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 1024 * 1024:
                            raise Problem(502, "upstream_invalid", "Invalid GitHub response")
                    return httpx.Response(200, content=bytes(content)).json()
        except httpx.TimeoutException as exc:
            raise Problem(504, "upstream_timeout", "GitHub timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise Problem(502, "upstream_error", "GitHub request failed") from exc

    def profile(self, handle: str) -> Profile:
        from urllib.parse import quote

        return self.parse_profile(
            self.request(
                "GET",
                f"https://api.github.com/users/{quote(handle, safe='')}",
                headers={"Accept": "application/vnd.github+json"},
            )
        )

    def parse_profile(self, data: Any) -> Profile:
        try:
            return Profile.model_validate(data)
        except ValidationError as exc:
            raise Problem(502, "upstream_invalid", "Invalid GitHub response") from exc

    def identity(
        self, code: str, verifier: str, client_id: str, secret: str, callback: str
    ) -> tuple[Profile, str]:
        token_data = self.request(
            "POST",
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": secret,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": callback,
            },
        )
        if not isinstance(token_data, dict) or not isinstance(token_data.get("access_token"), str):
            raise Problem(502, "oauth_exchange_failed", "GitHub authorization failed")
        headers = {
            "Authorization": f"Bearer {token_data['access_token']}",
            "Accept": "application/vnd.github+json",
        }
        profile = self.parse_profile(
            self.request("GET", "https://api.github.com/user", headers=headers)
        )
        emails = self.request("GET", "https://api.github.com/user/emails", headers=headers)
        if isinstance(emails, list):
            for email in emails:
                if (
                    isinstance(email, dict)
                    and email.get("primary") is True
                    and email.get("verified") is True
                    and isinstance(email.get("email"), str)
                ):
                    return profile, email["email"]
        raise Problem(403, "oauth_email_required", "A verified GitHub email is required")
