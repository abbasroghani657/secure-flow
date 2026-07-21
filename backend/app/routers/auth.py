from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import User
from ..ratelimit import limiter
from ..schemas import TokenResponse, UserCreate, UserLogin, UserRead
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _token_response(user: User) -> TokenResponse:
    token = create_access_token(subject=str(user.id))
    return TokenResponse(
        access_token=token,
        user=UserRead(id=user.id, name=user.name, email=user.email, created_at=user.created_at),
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
    return UserRead(id=current.id, name=current.name, email=current.email, created_at=current.created_at)
