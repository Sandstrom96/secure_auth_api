from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from app.db.session import get_session
from app.schemas.user import UserCreate, UserPublic, UserDeleteResponse
from app.models.user import User, UserRole
from app.core.security import get_password_hash
from app.api.deps import get_current_user, has_required_role
from app.schemas.error import APIErrorResponse, AuthException

router = APIRouter()


@router.post(
    "/",
    response_model=UserPublic,
    summary="Create new user",
    description="Create a new user in the system. Checks if the email is already registered.",
)
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


@router.delete(
    "/{user_id}",
    response_model=UserDeleteResponse,
    summary="Deactivate a user",
    description="Soft-deletes a user by setting is_active to False. Requires Admin privileges.",
)
def delete_user(
    user_id: int,
    session: Session = Depends(get_session),
    admin_user: User = Depends(has_required_role(UserRole.ADMIN)),
):
    user = session.get(User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin_user.id:
        raise AuthException(
            message="Cant delete yourself", error_code="SELF_DELETION_FORBIDDEN"
        )

    user.is_active = False
    session.add(user)
    session.commit()

    return UserDeleteResponse(message="User deactivated successfully", user_id=user_id)
