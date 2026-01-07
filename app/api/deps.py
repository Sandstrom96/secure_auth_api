from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlmodel import Session, select
from app.core.config import settings
from app.core.security import ALGORITHM
from app.db.session import get_session
from app.models.user import User

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/login/access-token")


def get_current_user(
    session: Session = Depends(get_session), token: str = Depends(reusable_oauth2)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token=token, key=settings.SECRET_KEY, algorithms=[ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    query = select(User).where(User.email == email)
    result = session.exec(query)
    user = result.first()

    if not user:
        raise credentials_exception

    return user
