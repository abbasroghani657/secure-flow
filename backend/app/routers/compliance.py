"""Compliance readiness — SOC 2 / PCI / ISO / GDPR / HIPAA control scoring."""

from fastapi import APIRouter

from ..compliance import build_compliance
from ..deps import CurrentUser, SessionDep
from ..schemas import ComplianceOverview

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("", response_model=ComplianceOverview)
def compliance_overview(current: CurrentUser, session: SessionDep) -> ComplianceOverview:
    return build_compliance(session, current.current_org_id)
