from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError

from app.db.session import get_session
from app.models.user import User, RefreshToken
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    REFRESH_TOKEN_EXPIRE_DAYS,
    SECRET_KEY,
    ALGORITHM,
)
from app.schemas.token import Token, TokenRefresh

router = APIRouter()


@router.post("/access-token", response_model=Token)
def login_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    OAuth2 compatible token login, get an access token for future requests.
    """

    # Retrieve the user from the database using the email provided in the form
    query = select(User).where(User.email == form_data.username)
    result = session.exec(query)
    user = result.first()

    # Verify that the user exists AND that the password is correct.
    # We use the same error message for both cases to avoid leaking information
    # about which emails exist in the system.
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    # Generate a time-limited access token (JWT)
    access_token = create_access_token(user.id)

    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token, jti = create_refresh_token(user.id, expires_delta=expire)

    db_refresh_token = RefreshToken(user_id=user.id, jti=jti, expires_at=expire)

    session.add(db_refresh_token)
    session.commit()
    session.refresh(db_refresh_token)

    # Return the token and type according to the OAuth2 standard
    return Token(
        access_token=access_token, token_type="bearer", refresh_token=refresh_token
    )


@router.post("/refresh", response_model=Token)
def refresh_token(refresh_token: TokenRefresh, session: Session = Depends(get_session)):
    """
    Exchange a valid refresh token for a new access token and a new refresh token (rotation).
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            refresh_token.refresh_token, SECRET_KEY, algorithms=[ALGORITHM]
        )
        token_type = payload.get("type")
        payload_jti = payload.get("jti")

        if (
            token_type != "refresh"
            or not payload_jti
            or str(payload.get("sub")) != str(token.user_id)
        ):
            raise credentials_exception

    except JWTError:
        raise credentials_exception
    except Exception:
        raise credentials_exception

    query = select(RefreshToken).where(
        RefreshToken.jti == payload_jti,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.now(timezone.utc),
    )
    result = session.exec(query)
    token = result.first()

    if not token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    token.is_revoked = True
    session.add(token)

    new_access_token = create_access_token(token.user_id)

    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token, jti = create_refresh_token(token.user_id, expires_delta=expire)

    db_refresh_token = RefreshToken(user_id=token.user_id, jti=jti, expires_at=expire)

    session.add(db_refresh_token)
    session.commit()
    session.refresh(db_refresh_token)

    return Token(
        access_token=new_access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
    )


@router.post("/logout")
def logout(refresh_token: TokenRefresh, session: Session = Depends(get_session)):
    query = select(RefreshToken).where(
        RefreshToken.refresh_token == refresh_token.refresh_token,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.now(timezone.utc),
    )
    result = session.exec(query)
    token = result.first()

    if not token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    token.is_revoked = True

    session.add(token)
    session.commit()
