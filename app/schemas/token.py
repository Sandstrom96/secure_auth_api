from sqlmodel import SQLModel


class Token(SQLModel):
    access_token: str
    token_type: str
    refresh_token: str


class TokenRefresh(SQLModel):
    refresh_token: str
