from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select

from .database import get_session
from .models import ApiToken, User
from .security import decode_access_token
from .tokens import API_TOKEN_PREFIX, token_prefix, verify_api_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

SessionDep = Annotated[Session, Depends(get_session)]


def _user_from_api_token(session: Session, token: str) -> User | None:
    """Resolve a machine token (ptx_...) used by the CLI / CI pipelines."""
    row = session.exec(
        select(ApiToken).where(
            ApiToken.prefix == token_prefix(token),
            ApiToken.revoked == False,  # noqa: E712
        )
    ).first()
    if not row or not verify_api_token(token, row.hashed_token):
        return None
    row.last_used_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return session.get(User, row.owner_id)


def get_current_user(
    session: SessionDep,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # Machine tokens (CLI/CI) authenticate the same endpoints as a logged-in user.
    if token.startswith(API_TOKEN_PREFIX):
        user = _user_from_api_token(session, token)
        if user is None:
            raise credentials_exc
        return user

    subject = decode_access_token(token)
    if subject is None:
        raise credentials_exc
    user = session.get(User, int(subject)) if subject.isdigit() else None
    if user is None:
        raise credentials_exc
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
