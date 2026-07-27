from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import (
    ApiToken, Integration, Scan, Schedule, Target, User,
)
from ..ratelimit import limiter
from ..schemas import (
    AccountDelete, PasswordChange, ProfileUpdate,
    TokenResponse, UserCreate, UserLogin, UserRead,
)
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _token_response(user: User) -> TokenResponse:
    token = create_access_token(subject=str(user.id))
    return TokenResponse(
        access_token=token,
        user=UserRead(id=user.id, name=user.name, email=user.email, plan=user.plan, created_at=user.created_at),
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, data: UserCreate, session: SessionDep) -> TokenResponse:
    email = data.email.lower()
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    user = User(
        email=email,
        name=data.name.strip(),
        hashed_password=hash_password(data.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, data: UserLogin, session: SessionDep) -> TokenResponse:
    user = session.exec(select(User).where(User.email == data.email.lower())).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    return _token_response(user)


@router.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
def login_form(request: Request, form: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep) -> TokenResponse:
    """OAuth2 password flow — lets the interactive /docs 'Authorize' button work."""
    user = session.exec(select(User).where(User.email == form.username.lower())).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    return _token_response(user)


@router.get("/me", response_model=UserRead)
def me(current: CurrentUser) -> UserRead:
    return UserRead(id=current.id, name=current.name, email=current.email, plan=current.plan, created_at=current.created_at)


@router.patch("/me", response_model=UserRead)
def update_profile(data: ProfileUpdate, current: CurrentUser, session: SessionDep) -> UserRead:
    current.name = data.name
    session.add(current)
    session.commit()
    session.refresh(current)
    return UserRead(id=current.id, name=current.name, email=current.email, plan=current.plan, created_at=current.created_at)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(data: PasswordChange, current: CurrentUser, session: SessionDep) -> None:
    if not verify_password(data.current_password, current.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    current.hashed_password = hash_password(data.new_password)
    session.add(current)
    session.commit()


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(data: AccountDelete, current: CurrentUser, session: SessionDep) -> None:
    """Permanently delete the account and everything owned by it. Password-gated."""
    if not verify_password(data.password, current.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password is incorrect")
    uid = current.id
    # Remove owned data first (scans cascade their findings via the relationship).
    for scan in session.exec(select(Scan).where(Scan.owner_id == uid)).all():
        session.delete(scan)
    for model in (Target, Schedule, Integration, ApiToken):
        for row in session.exec(select(model).where(model.owner_id == uid)).all():
            session.delete(row)
    session.delete(current)
    session.commit()
