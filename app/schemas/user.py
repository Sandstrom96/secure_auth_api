from sqlmodel import SQLModel


# We inherit from SQLModel to get validation, but we do NOT set table=True
# because this is just a data container (Pydantic model), not a database table.
class UserCreate(SQLModel):
    email: str
    password: str
