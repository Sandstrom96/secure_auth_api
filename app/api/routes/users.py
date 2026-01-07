from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from app.db.session import get_session
from app.schemas.user import UserCreate, UserPublic
from app.models.user import User
from app.core.security import get_password_hash

router = APIRouter()


@router.post("/", response_model=UserPublic)
def create_user(user_in: UserCreate, session: Session = Depends(get_session)):
    query = select(User).where(User.email == user_in.email)
    result = session.exec(query)
    user = result.first()

    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )

    user = User(
        email=user_in.email, hashed_password=get_password_hash(user_in.password)
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user
