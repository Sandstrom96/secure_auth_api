from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.api.routes import users, login
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from app.core.limiter import limiter
from app.schemas.error import AuthException
from datetime import datetime


app = FastAPI()
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(login.router, prefix="/login", tags=["Login"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(AuthException)
async def auth_exception_handler(request: Request, exc: AuthException):
    error_content = {
        "error_code": exc.error_code,
        "message": exc.message,
        "timestamp": datetime.now().isoformat(),
    }

    return JSONResponse(status_code=401, content=error_content)
