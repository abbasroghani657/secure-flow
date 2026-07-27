"""Organizations & teams — the enterprise collaboration layer.

Members share a workspace's targets, scans, schedules and risk register. Roles
(owner > admin > member > viewer) gate what each can do. Invites bring teammates
in; an audit trail records who did what.
"""

import secrets as _secrets

from fastapi import APIRouter, HTTPException, status
from sqlmodel import func, select

from ..access import get_membership, log_event, require_role
from ..config import settings
from ..deps import CurrentUser, SessionDep
from ..models import (
    ROLE_RANK, AuditEvent, Invitation, Membership, Organization, User,
)
from ..plans import check_can_use_teams
from ..schemas import (
    AuditEventRead, InvitationCreated, InvitationRead, InviteCreate, InvitePreview,
    MemberRead, OrgCreate, OrgDetail, OrgRename, OrgSummary, RoleUpdate,
)

router = APIRouter(prefix="/api/orgs", tags=["orgs"])

_ASSIGNABLE = {"viewer", "member", "admin", "owner"}


def _member_count(session, org_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(Membership).where(Membership.org_id == org_id)
    ).one()


def _members(session, org_id: int) -> list[MemberRead]:
    rows = session.exec(
        select(Membership, User).where(Membership.org_id == org_id, Membership.user_id == User.id)
    ).all()
    out = []
    for m, u in rows:
        out.append(MemberRead(user_id=u.id, name=u.name, email=u.email, role=m.role, joined_at=m.created_at))
    out.sort(key=lambda x: (-ROLE_RANK.get(x.role, 0), x.name.lower()))
    return out


# --------------------------------------------------------------------------- #
# Orgs
# --------------------------------------------------------------------------- #

@router.get("", response_model=list[OrgSummary])
def list_orgs(current: CurrentUser, session: SessionDep) -> list[OrgSummary]:
    rows = session.exec(
        select(Membership, Organization)
        .where(Membership.user_id == current.id, Membership.org_id == Organization.id)
    ).all()
    return [
        OrgSummary(id=o.id, name=o.name, role=m.role, personal=o.personal,
                   member_count=_member_count(session, o.id))
        for m, o in rows
    ]


@router.get("/current", response_model=OrgDetail)
def current_org(current: CurrentUser, session: SessionDep) -> OrgDetail:
    m = get_membership(session, current)
    org = session.get(Organization, m.org_id)
    invites = []
    if ROLE_RANK.get(m.role, 0) >= ROLE_RANK["admin"]:
        invites = [
            InvitationRead.model_validate(i, from_attributes=True)
            for i in session.exec(
                select(Invitation).where(Invitation.org_id == org.id, Invitation.status == "pending")
            ).all()
        ]
    return OrgDetail(
        id=org.id, name=org.name, personal=org.personal, my_role=m.role,
        members=_members(session, org.id), invitations=invites,
    )


@router.post("", response_model=OrgSummary, status_code=status.HTTP_201_CREATED)
def create_org(data: OrgCreate, current: CurrentUser, session: SessionDep) -> OrgSummary:
    check_can_use_teams(current)   # creating team workspaces is a Business feature
    org = Organization(name=data.name, personal=False, created_by_id=current.id)
    session.add(org)
    session.commit()
    session.refresh(org)
    session.add(Membership(org_id=org.id, user_id=current.id, role="owner"))
    current.current_org_id = org.id
    session.add(current)
    session.commit()
    log_event(session, org.id, current, "org.created", org.name)
    return OrgSummary(id=org.id, name=org.name, role="owner", personal=False, member_count=1)


@router.post("/switch/{org_id}", response_model=OrgSummary)
def switch_org(org_id: int, current: CurrentUser, session: SessionDep) -> OrgSummary:
    m = get_membership(session, current, org_id)   # 403 if not a member
    org = session.get(Organization, org_id)
    current.current_org_id = org_id
    session.add(current)
    session.commit()
    return OrgSummary(id=org.id, name=org.name, role=m.role, personal=org.personal,
                      member_count=_member_count(session, org.id))


@router.patch("/current", response_model=OrgDetail)
def rename_org(data: OrgRename, current: CurrentUser, session: SessionDep) -> OrgDetail:
    require_role(session, current, "admin")
    org = session.get(Organization, current.current_org_id)
    org.name = data.name
    session.add(org)
    session.commit()
    log_event(session, org.id, current, "org.renamed", data.name)
    return current_org(current, session)


# --------------------------------------------------------------------------- #
# Invitations
# --------------------------------------------------------------------------- #

def _invite_out(inv: Invitation) -> InvitationCreated:
    base = InvitationRead.model_validate(inv, from_attributes=True)
    url = f"{settings.frontend_url.rstrip('/')}/invite/{inv.token}"
    return InvitationCreated(**base.model_dump(), token=inv.token, accept_url=url)


@router.post("/current/invitations", response_model=InvitationCreated, status_code=status.HTTP_201_CREATED)
def invite_member(data: InviteCreate, current: CurrentUser, session: SessionDep) -> InvitationCreated:
    require_role(session, current, "admin")
    check_can_use_teams(current)
    role = data.role if data.role in {"viewer", "member", "admin"} else "member"
    email = data.email.lower()
    org_id = current.current_org_id

    # Already a member?
    existing_member = session.exec(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == User.id, User.email == email)
    ).first()
    if existing_member:
        raise HTTPException(status.HTTP_409_CONFLICT, "That person is already a member.")
    # Re-use a pending invite for the same email.
    pending = session.exec(
        select(Invitation).where(Invitation.org_id == org_id, Invitation.email == email, Invitation.status == "pending")
    ).first()
    if pending:
        pending.role = role
        session.add(pending)
        session.commit()
        session.refresh(pending)
        return _invite_out(pending)

    inv = Invitation(org_id=org_id, email=email, role=role,
                     token=_secrets.token_urlsafe(24), invited_by_id=current.id)
    session.add(inv)
    session.commit()
    session.refresh(inv)
    log_event(session, org_id, current, "member.invited", f"{email} as {role}")
    return _invite_out(inv)


@router.delete("/current/invitations/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invite(invite_id: int, current: CurrentUser, session: SessionDep) -> None:
    require_role(session, current, "admin")
    inv = session.get(Invitation, invite_id)
    if not inv or inv.org_id != current.current_org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invitation not found")
    inv.status = "revoked"
    session.add(inv)
    session.commit()
    log_event(session, inv.org_id, current, "invite.revoked", inv.email)


@router.get("/invitations/{token}", response_model=InvitePreview)
def preview_invite(token: str, current: CurrentUser, session: SessionDep) -> InvitePreview:
    inv = session.exec(select(Invitation).where(Invitation.token == token)).first()
    if not inv or inv.status != "pending":
        return InvitePreview(org_name="", role="", email=current.email, valid=False,
                             reason="This invitation is no longer valid.")
    org = session.get(Organization, inv.org_id)
    if inv.email.lower() != current.email.lower():
        return InvitePreview(org_name=org.name if org else "", role=inv.role, email=inv.email,
                             valid=False, reason=f"This invite is for {inv.email}. Sign in as that user to accept.")
    return InvitePreview(org_name=org.name if org else "", role=inv.role, email=inv.email, valid=True)


@router.post("/invitations/{token}/accept", response_model=OrgSummary)
def accept_invite(token: str, current: CurrentUser, session: SessionDep) -> OrgSummary:
    inv = session.exec(select(Invitation).where(Invitation.token == token)).first()
    if not inv or inv.status != "pending":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This invitation is no longer valid.")
    if inv.email.lower() != current.email.lower():
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"This invite is for {inv.email}.")
    already = session.exec(
        select(Membership).where(Membership.org_id == inv.org_id, Membership.user_id == current.id)
    ).first()
    if not already:
        session.add(Membership(org_id=inv.org_id, user_id=current.id, role=inv.role))
    inv.status = "accepted"
    session.add(inv)
    current.current_org_id = inv.org_id
    session.add(current)
    session.commit()
    log_event(session, inv.org_id, current, "member.joined", current.email)
    org = session.get(Organization, inv.org_id)
    return OrgSummary(id=org.id, name=org.name, role=inv.role, personal=org.personal,
                      member_count=_member_count(session, org.id))


# --------------------------------------------------------------------------- #
# Members
# --------------------------------------------------------------------------- #

def _owner_count(session, org_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(Membership)
        .where(Membership.org_id == org_id, Membership.role == "owner")
    ).one()


@router.patch("/current/members/{user_id}", response_model=MemberRead)
def change_role(user_id: int, data: RoleUpdate, current: CurrentUser, session: SessionDep) -> MemberRead:
    require_role(session, current, "admin")
    if data.role not in _ASSIGNABLE:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {sorted(_ASSIGNABLE)}")
    if data.role == "owner":
        require_role(session, current, "owner")   # only an owner can crown another owner
    org_id = current.current_org_id
    m = session.exec(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id)
    ).first()
    if not m:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    if m.role == "owner" and data.role != "owner" and _owner_count(session, org_id) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "An organization must keep at least one owner.")
    m.role = data.role
    session.add(m)
    session.commit()
    log_event(session, org_id, current, "role.changed", f"user {user_id} -> {data.role}")
    u = session.get(User, user_id)
    return MemberRead(user_id=u.id, name=u.name, email=u.email, role=m.role, joined_at=m.created_at)


@router.delete("/current/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(user_id: int, current: CurrentUser, session: SessionDep) -> None:
    org_id = current.current_org_id
    # Members may remove themselves (leave); removing others needs admin.
    if user_id != current.id:
        require_role(session, current, "admin")
    m = session.exec(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id)
    ).first()
    if not m:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    if m.role == "owner" and _owner_count(session, org_id) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Transfer ownership before removing the last owner.")
    session.delete(m)
    # If the removed user was acting in this org, drop them back to a personal org.
    victim = session.get(User, user_id)
    if victim and victim.current_org_id == org_id:
        other = session.exec(
            select(Membership).where(Membership.user_id == user_id, Membership.org_id != org_id)
        ).first()
        victim.current_org_id = other.org_id if other else None
        session.add(victim)
    session.commit()
    log_event(session, org_id, current, "member.removed", f"user {user_id}")


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

@router.get("/current/audit", response_model=list[AuditEventRead])
def audit_log(current: CurrentUser, session: SessionDep, limit: int = 100) -> list[AuditEventRead]:
    require_role(session, current, "admin")
    rows = session.exec(
        select(AuditEvent).where(AuditEvent.org_id == current.current_org_id)
        .order_by(AuditEvent.created_at.desc()).limit(min(limit, 200))
    ).all()
    return [AuditEventRead.model_validate(r, from_attributes=True) for r in rows]
