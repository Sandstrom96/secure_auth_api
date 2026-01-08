from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt
from app.core.config import settings
import uuid
from sqlmodel import select, Session
from app.models.user import User
from app.schemas.error import AuthException

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


# Create a "context" for handling passwords.
# schemes=["bcrypt"]: Tells passlib to use the bcrypt algorithm (secure standard).
# deprecated="auto": Allows passlib to upgrade hashes automatically if we change settings later.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Checks if a plain-text password matches the hashed version.
    Returns True if they match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Takes a plain-text password and returns a secure hash string.
    This hash is what we save in the database.
    """
    return pwd_context.hash(password)


def create_access_token(
    subject: str | any, expires_delta: timedelta | None = None
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: str, expires_delta: timedelta | None = None) -> str:
    jti = str(uuid.uuid4())

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh", "jti": jti}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti


def authenticate_user(session: Session, email: str, password: str) -> User:
    """
    Authenticates a user by checking their email and password.
    Returns the user object if successful, otherwise raises an AuthException.
    """
    # Retrieve the user from the database using the email provided in the form
    query = select(User).where(User.email == email)
    user = session.exec(query).first()

    if not user:
        raise AuthException(
            message="Incorrect email or password", error_code="INVALID_CREDENTIALS"
        )

    if user.is_email_verified is False:
        raise AuthException(
            message="Email not verified", error_code="EMAIL_NOT_VERIFIED"
        )
    
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise AuthException(
            message="Account is locked. Please try again later.",
            error_code="ACCOUNT_LOCKED",
        )

    # Verify that the user exists AND that the password is correct.
    # We use the same error message for both cases to avoid leaking information
    # about which emails exist in the system.
    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)
        session.add(user)
        session.commit()

        raise AuthException(
            message="Incorrect email or password", error_code="INVALID_CREDENTIALS"
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    session.add(user)
    session.commit()
    session.refresh(user)

    return user
