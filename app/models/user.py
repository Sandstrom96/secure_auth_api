from sqlmodel import SQLModel, Field
import enum


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
    hashed_password: str
    role: UserRole = Field(default=UserRole.USER)
    is_active: bool = Field(default=True)
