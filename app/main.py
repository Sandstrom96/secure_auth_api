from fastapi import FastAPI
from app.api.routes import users, login

app = FastAPI()
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(login.router, prefix="/login", tags=["Login"])
