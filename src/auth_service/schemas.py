from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EmailInput(Input):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.casefold()


class Login(EmailInput):
    password: str = Field(min_length=1, max_length=128)


class Register(EmailInput):
    password: str = Field(min_length=15, max_length=128)
    display_name: str = Field(default="", max_length=100)


class TokenInput(Input):
    token: str = Field(min_length=1, max_length=2048)


class Reset(TokenInput):
    password: str = Field(min_length=15, max_length=128)


class PasswordChange(Input):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=15, max_length=128)


class UserPatch(Input):
    display_name: str = Field(max_length=100)


class AdminPatch(Input):
    role: str | None = None
    disabled: bool | None = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str | None) -> str | None:
        if value is not None and value not in {"user", "admin"}:
            raise ValueError("Invalid role")
        return value
