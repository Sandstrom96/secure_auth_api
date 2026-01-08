from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.db.session import get_session
from app.models.user import User
from app.core.security import verify_password, create_access_token
from app.schemas.token import Token

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
    token = create_access_token(user.email)

    # Return the token and type according to the OAuth2 standard
    return Token(access_token=token, token_type="bearer")
