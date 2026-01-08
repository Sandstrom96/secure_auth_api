from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlmodel import Session, select

from app.core.config import settings
from app.core.security import ALGORITHM
from app.db.session import get_session
from app.models.user import User

# This tells Swagger UI where to send the user's credentials to get a token.
# The "Authorize" button will use this URL.
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/login/access-token")


def get_current_user(
    session: Session = Depends(get_session), token: str = Depends(reusable_oauth2)
) -> User:
    """
    Dependency that validates the access token and retrieves the current user.
    Used on endpoints that require authentication.
    """

    # Prepare a standard 401 Unauthorized exception
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Try to decode the token using our secret key and algorithm
        payload = jwt.decode(
            token=token, key=settings.SECRET_KEY, algorithms=[ALGORITHM]
        )

        # Retrieve the 'sub' (subject/email) from the token payload
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception

    except JWTError:
        # If the token is invalid, forged, or expired -> raise exception
        raise credentials_exception

    # Fetch the user from the DB to ensure they still exist and are active
    query = select(User).where(User.email == email)
    result = session.exec(query)
    user = result.first()

    if not user:
        raise credentials_exception

    return user
