"""Unified risk register + attack paths (ASPM) — one view of an owner's real risk
across every scan and target."""

from fastapi import APIRouter

from ..deps import CurrentUser, SessionDep
from ..risk import build_risk_overview
from ..schemas import RiskOverview

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("", response_model=RiskOverview)
def risk_overview(current: CurrentUser, session: SessionDep) -> RiskOverview:
    return build_risk_overview(session, current.id)
