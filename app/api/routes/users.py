from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from app.db.session import get_session
from app.schemas.user import UserCreate, UserPublic
from app.models.user import User, UserRole
from app.core.security import get_password_hash
from app.api.deps import get_current_user, has_required_role

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


@router.get("/me", response_model=User)
def read_user_me(current_user: User = Depends(get_current_user)):
    """
    Get current user.
    """
    return current_user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    session: Session = Depends(get_session),
    admin_user: User = Depends(has_required_role(UserRole.ADMIN)),
):
    user = session.get(User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id:
        raise HTTPException(status_code=403, detail="Cant delete yourself")

    user.is_active = False
    session.add(user)
    session.commit()
