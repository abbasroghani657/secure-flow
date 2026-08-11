"""Organization scoping + role-based access control.

Every shared resource (targets, scans, schedules, integrations, tokens) belongs to
an organization. A user acts inside exactly one org at a time (``current_org_id``)
and holds a role there — viewer < member < admin < owner. Reads are open to any
member; writes need member+; team management needs admin+.
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlmodel import select

from .models import ROLE_RANK, Membership, Organization


def ensure_personal_org(session, user) -> Organization:
    """Give a brand-new user their own workspace and make it active. Idempotent."""
    if user.current_org_id:
        return session.get(Organization, user.current_org_id)
    org = Organization(name=f"{user.name}'s workspace", personal=True, created_by_id=user.id)
    session.add(org)
    session.flush()
    session.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
    user.current_org_id = org.id
    session.add(user)
    session.flush()
    session.refresh(user)
    return org


def current_org_id(user) -> int:
    if not user.current_org_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "No active organization")
    return user.current_org_id


def get_membership(session, user, org_id: int | None = None) -> Membership:
    oid = org_id if org_id is not None else current_org_id(user)
    m = session.exec(
        select(Membership).where(Membership.org_id == oid, Membership.user_id == user.id)
    ).first()
    if not m:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this organization")
    return m


def get_role(session, user, org_id: int | None = None) -> str:
    return get_membership(session, user, org_id).role


def require_role(session, user, min_role: str, org_id: int | None = None) -> str:
    role = get_role(session, user, org_id)
    if ROLE_RANK.get(role, -1) < ROLE_RANK.get(min_role, 99):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"This action needs the '{min_role}' role or higher. Your role is '{role}'.",
        )
    return role


def require_write(session, user, org_id: int | None = None) -> str:
    """Creating or changing resources needs at least member (viewers are read-only)."""
    if not user.email_verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, 
            "Please verify your email address to perform write actions (like starting scans)."
        )
    return require_role(session, user, "member", org_id)


def get_org(session, user) -> Organization:
    return session.get(Organization, current_org_id(user))


def log_event(session, org_id: int, actor, action: str, detail: str = "") -> None:
    """Append to the org's audit trail. Never raises into the caller."""
    from .models import AuditEvent
    try:
        session.add(AuditEvent(
            org_id=org_id, actor_id=getattr(actor, "id", None),
            actor_email=getattr(actor, "email", ""), action=action, detail=detail,
        ))
        session.commit()
    except Exception:  # noqa: BLE001
        session.rollback()
