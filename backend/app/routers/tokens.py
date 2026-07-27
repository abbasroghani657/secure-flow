"""Personal API tokens for the CLI and CI/CD pipelines.

Create a token (shown once), use it as a Bearer token from the ``pentrixa`` CLI or
the GitHub Action. A Pro feature (see ``check_api_access``).
"""

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import ApiToken
from ..plans import check_api_access
from ..schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenRead
from ..tokens import generate_api_token

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


@router.get("", response_model=list[ApiTokenRead])
def list_tokens(current: CurrentUser, session: SessionDep) -> list[ApiToken]:
    return session.exec(
        select(ApiToken).where(ApiToken.owner_id == current.id).order_by(ApiToken.created_at)
    ).all()


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(data: ApiTokenCreate, current: CurrentUser, session: SessionDep) -> ApiTokenCreated:
    check_api_access(current)
    full, prefix, hashed = generate_api_token()
    row = ApiToken(owner_id=current.id, name=data.name or "API token",
                   prefix=prefix, hashed_token=hashed)
    session.add(row)
    session.commit()
    session.refresh(row)
    # The only time the raw token is ever returned.
    return ApiTokenCreated(
        id=row.id, name=row.name, prefix=row.prefix, created_at=row.created_at,
        last_used_at=row.last_used_at, revoked=row.revoked, token=full,
    )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(token_id: int, current: CurrentUser, session: SessionDep) -> None:
    row = session.get(ApiToken, token_id)
    if not row or row.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    row.revoked = True
    session.add(row)
    session.commit()
