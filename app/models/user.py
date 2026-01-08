from sqlmodel import SQLModel, Field
from datetime import datetime, timezone
import enum
import uuid


# Using (str, enum.Enum) makes it a "String Enum".
# 1. str: Allows it to be automatically converted to JSON (text) by FastAPI.
# 2. enum.Enum: Enforces that only specific values ('user', 'admin') are allowed.
class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


# table=True tells SQLModel that this class corresponds to a table in the DB.
class User(SQLModel, table=True):
    # default=None allows creating a User object in Python before it has an ID from the DB.
    id: int | None = Field(primary_key=True, default=None)
    email: str = Field(unique=True, index=True)
    is_email_verified: bool = Field(default=False)
    hashed_password: str
    role: UserRole = Field(default=UserRole.USER)
    failed_login_attempts: int = Field(default=0)
    locked_until: datetime | None = Field(default=None)
    is_active: bool = Field(default=True)


class RefreshToken(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    jti: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        unique=True,
        index=True,
        nullable=False,
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    is_revoked: bool = Field(default=False)
