class Problem(Exception):
    def __init__(self, status: int, code: str, detail: str) -> None:
        self.status = status
        self.code = code
        self.detail = detail
        super().__init__(code)


def unauthorized() -> Problem:
    return Problem(401, "invalid_credentials", "Authentication failed")
