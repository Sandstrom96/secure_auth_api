from sqlmodel import SQLModel


class UserCreate(SQLModel):
    email: str
    password: str
