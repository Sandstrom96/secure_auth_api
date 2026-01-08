from sqlmodel import SQLModel
from app.models.user import UserRole


# We inherit from SQLModel to get validation, but we do NOT set table=True
# because this is just a data container (Pydantic model), not a database table.
class UserCreate(SQLModel):
    email: str
    password: str


class UserPublic(SQLModel):
    id: int
    email: str
    role: UserRole
    is_active: bool


class UserDeleteResponse(SQLModel):
    message: str
    user_id: int
