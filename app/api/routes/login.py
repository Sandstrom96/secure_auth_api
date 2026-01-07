from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from app.db.session import get_session
from sqlmodel import Session, select
from app.models.user import User
from app.core.security import verify_password, create_access_token
from app.schemas.token import Token

router = APIRouter()


@router.post("/access-token", response_model=Token)
def login_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    query = select(User).where(User.email == form_data.username)
    result = session.exec(query)
    user = result.first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token(user.email)
    return Token(access_token=token, token_type="bearer")
