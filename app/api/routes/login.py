from fastapi import APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError
from app.schemas.error import AuthException

from app.db.session import get_session
from app.models.user import User, RefreshToken
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    REFRESH_TOKEN_EXPIRE_DAYS,
    authenticate_user,
)
from app.schemas.token import Token, TokenRefresh
from app.core.limiter import limiter
from app.schemas.user import UserLogoutResponse
from app.api.deps import get_valid_refresh_token

router = APIRouter()


@limiter.limit("5/minute")
@router.post(
    "/access-token",
    response_model=Token,
    summary="Login for access token",
    description="Authenticates user with email and password, returning both access and refresh tokens.",
)
def login_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    OAuth2 compatible token login, get an access token for future requests.
    """

    user = authenticate_user(
        session=session, email=form_data.username, password=form_data.password
    )

    # Generate a time-limited access token (JWT)
    access_token = create_access_token(user.id)

    expire = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token, jti = create_refresh_token(user.id, expires_delta=expire)

    expires_at = datetime.now(timezone.utc) + expire

    db_refresh_token = RefreshToken(user_id=user.id, jti=jti, expires_at=expires_at)

    session.add(db_refresh_token)
    session.commit()
    session.refresh(db_refresh_token)

    # Return the token and type according to the OAuth2 standard
    return Token(
        access_token=access_token, token_type="bearer", refresh_token=refresh_token
    )


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access token and a new rotated refresh token.",
)
def refresh_token(refresh_data: TokenRefresh, session: Session = Depends(get_session)):
    """
    Exchange a valid refresh token for a new access token and a new refresh token (rotation).
    """

    token = get_valid_refresh_token(
        session=session, token_string=refresh_data.refresh_token
    )

    token.is_revoked = True
    session.add(token)

    new_access_token = create_access_token(token.user_id)

    expire_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token, jti = create_refresh_token(
        token.user_id, expires_delta=expire_delta
    )

    db_refresh_token = RefreshToken(
        user_id=token.user_id,
        jti=jti,
        expires_at=datetime.now(timezone.utc) + expire_delta,
    )

    session.add(db_refresh_token)
    session.commit()

    return Token(
        access_token=new_access_token,
        token_type="bearer",
        refresh_token=new_refresh_token,
    )


@router.post(
    "/logout",
    response_model=UserLogoutResponse,
    summary="Logout user",
    description="Invalidates the provided refresh token by revoking it in the database.",
)
def logout(refresh_token: TokenRefresh, session: Session = Depends(get_session)):

    token = get_valid_refresh_token(session=session, token_string=refresh_token)

    token.is_revoked = True
    session.add(token)
    session.commit()

    return UserLogoutResponse(message="Successfully logged out", user_id=token.user_id)
