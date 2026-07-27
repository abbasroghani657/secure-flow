"""Outbound alert channels — Slack, Teams, Discord, or a generic webhook.

The user pastes an incoming-webhook URL from their own workspace; scan results are
POSTed there when they finish. A Pro feature (see ``check_can_integrate``).
"""

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..access import require_write
from ..deps import CurrentUser, SessionDep
from ..models import Integration
from ..notifications import test_integration
from ..plans import check_can_integrate
from ..schemas import IntegrationCreate, IntegrationRead, IntegrationUpdate

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

_KINDS = {"slack", "teams", "discord", "webhook"}
_EVENTS = {"critical_high", "new_only", "all"}


def _owned(session, org_id: int, integ_id: int) -> Integration:
    integ = session.get(Integration, integ_id)
    if not integ or integ.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found")
    return integ


def _validate(kind: str, events: str, target: str) -> None:
    if kind not in _KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {sorted(_KINDS)}")
    if events not in _EVENTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"events must be one of {sorted(_EVENTS)}")
    if not target.startswith("https://"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Webhook URL must be https://")


@router.get("", response_model=list[IntegrationRead])
def list_integrations(current: CurrentUser, session: SessionDep) -> list[Integration]:
    return session.exec(
        select(Integration).where(Integration.org_id == current.current_org_id).order_by(Integration.created_at)
    ).all()


@router.post("", response_model=IntegrationRead, status_code=status.HTTP_201_CREATED)
def create_integration(data: IntegrationCreate, current: CurrentUser, session: SessionDep) -> Integration:
    require_write(session, current)
    check_can_integrate(current)
    _validate(data.kind, data.events, data.target)
    integ = Integration(
        owner_id=current.id, org_id=current.current_org_id,
        kind=data.kind, name=data.name or data.kind.title(),
        target=data.target, events=data.events,
    )
    session.add(integ)
    session.commit()
    session.refresh(integ)
    return integ


@router.patch("/{integ_id}", response_model=IntegrationRead)
def update_integration(integ_id: int, data: IntegrationUpdate, current: CurrentUser, session: SessionDep) -> Integration:
    require_write(session, current)
    check_can_integrate(current)
    integ = _owned(session, current.current_org_id, integ_id)
    if data.target is not None or data.events is not None:
        _validate(integ.kind, data.events or integ.events, data.target or integ.target)
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(integ, field, value)
    session.add(integ)
    session.commit()
    session.refresh(integ)
    return integ


@router.post("/{integ_id}/test")
def test_existing(integ_id: int, current: CurrentUser, session: SessionDep) -> dict:
    integ = _owned(session, current.current_org_id, integ_id)
    ok = test_integration(integ.kind, integ.target)
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            "Could not deliver a test message. Check the webhook URL.")
    return {"delivered": True}


@router.delete("/{integ_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(integ_id: int, current: CurrentUser, session: SessionDep) -> None:
    require_write(session, current)
    integ = _owned(session, current.current_org_id, integ_id)
    session.delete(integ)
    session.commit()
