from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlmodel import Session, select

from app.core.config import settings
from app.core.security import ALGORITHM
from app.db.session import get_session
from app.models.user import User, UserRole

# This tells Swagger UI where to send the user's credentials to get a token.
# The "Authorize" button will use this URL.
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/login/access-token")

# Role power levels: Higher number means more authority
# This allows an ADMIN (10) to pass a check for a USER (1)
ROLE_HIERARCHY = {
    UserRole.USER: 1,
    UserRole.ADMIN: 10,
}


def get_current_user(
    session: Session = Depends(get_session), token: str = Depends(reusable_oauth2)
) -> User:
    """
    Dependency that validates the access token and retrieves the current user.
    Used on endpoints that require authentication.
    """
    print(token)
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

        # Retrieve the 'sub' (subject/id) from the token payload
        id: str = payload.get("sub")
        token_type = payload.get("type")
        if id is None or token_type != "access":
            raise credentials_exception

    except JWTError:
        # If the token is invalid, forged, or expired -> raise exception
        raise credentials_exception

    # Fetch the user from the DB to ensure they still exist and are active
    query = select(User).where(User.id == id)
    result = session.exec(query)
    user = result.first()

    if not user:
        raise credentials_exception

    return user


def has_required_role(required_role: UserRole):
    """
    Factory function that creates a dependency to check if a user
    has the minimum required role level to access a resource.
    """

    def role_checker(current_user: User = Depends(get_current_user)):
        # Get levels from hierarchy, default to 0 if role is unknown (deny access)
        user_level = ROLE_HIERARCHY.get(current_user.role, 0)
        required_level = ROLE_HIERARCHY.get(required_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have enough permissions for this action.",
            )
        return current_user

    return role_checker
