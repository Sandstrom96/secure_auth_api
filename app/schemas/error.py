from sqlmodel import SQLModel
from datetime import datetime


class APIErrorResponse(SQLModel):
    error_code: str
    message: str
    timestamp: datetime


class AuthException(Exception):
    def __init__(self, message: str, error_code: str = "AUTH_ERROR"):
        self.message = message
        self.error_code = error_code
