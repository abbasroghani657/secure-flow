from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import Target
from ..schemas import TargetCreate, TargetDetail, TargetRead, VerificationStep, VerifyResult
from ..scanner.checks import normalize_url
from ..verification import instructions, new_token, verify

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _detail(target: Target) -> TargetDetail:
    steps = [VerificationStep(**s) for s in instructions(target.host, target.verification_token)]
    base = TargetRead.model_validate(target, from_attributes=True)
    return TargetDetail(**base.model_dump(), instructions=steps)


@router.post("", response_model=TargetDetail, status_code=status.HTTP_201_CREATED)
def create_target(data: TargetCreate, current: CurrentUser, session: SessionDep) -> TargetDetail:
    try:
        url = normalize_url(data.url)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid URL")
    host = urlparse(url).hostname
    if not host:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Could not parse a hostname from the URL")

    existing = session.exec(
        select(Target).where(Target.owner_id == current.id, Target.host == host)
    ).first()
    if existing:
        return _detail(existing)

    target = Target(
        owner_id=current.id,
        url=f"{urlparse(url).scheme}://{host}",
        host=host,
        label=data.label,
        verification_token=new_token(),
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return _detail(target)


@router.get("", response_model=list[TargetRead])
def list_targets(current: CurrentUser, session: SessionDep) -> list[TargetRead]:
    targets = session.exec(
        select(Target).where(Target.owner_id == current.id).order_by(Target.created_at.desc())
    ).all()
    return [TargetRead.model_validate(t, from_attributes=True) for t in targets]


@router.get("/{target_id}", response_model=TargetDetail)
def get_target(target_id: int, current: CurrentUser, session: SessionDep) -> TargetDetail:
    target = session.get(Target, target_id)
    if not target or target.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return _detail(target)


@router.post("/{target_id}/verify", response_model=VerifyResult)
def verify_target(target_id: int, current: CurrentUser, session: SessionDep) -> VerifyResult:
    target = session.get(Target, target_id)
    if not target or target.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    if target.verified:
        return VerifyResult(verified=True, method=target.verification_method, message="Already verified.")

    method = verify(target.host, target.verification_token)
    if method:
        target.verified = True
        target.verification_method = method
        target.verified_at = datetime.now(timezone.utc)
        session.add(target)
        session.commit()
        return VerifyResult(verified=True, method=method, message=f"Verified via {method}.")
    return VerifyResult(
        verified=False,
        message="Could not find the verification token yet. DNS changes can take a few minutes to propagate.",
    )


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: int, current: CurrentUser, session: SessionDep) -> None:
    target = session.get(Target, target_id)
    if not target or target.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    session.delete(target)
    session.commit()
