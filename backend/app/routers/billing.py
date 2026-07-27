"""Plan and usage info for the current user.

Read-only for now: it tells the frontend which plan the user is on, the limits,
and how much they have used, so the UI can show usage meters and upgrade prompts.
Actually changing plans will happen through the billing provider (Stripe) once
that is wired; there is deliberately no self-serve "make me Pro for free" here.
"""

from fastapi import APIRouter

from ..deps import CurrentUser, SessionDep
from ..plans import PLAN_LIMITS, usage_for

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.get("/plan")
def my_plan(current: CurrentUser, session: SessionDep) -> dict:
    return usage_for(session, current)


@router.get("/plans")
def all_plans() -> dict:
    """Public plan matrix, so the pricing page can render limits from one source."""
    out = {}
    for key, lim in PLAN_LIMITS.items():
        out[key] = {
            "label": lim["label"],
            "max_targets": lim["max_targets"],
            "scans_per_month": lim["scans_per_month"],
            "scheduling": lim["scheduling"],
            "teams": lim["teams"],
            "scan_types": sorted(lim["scan_types"]),
        }
    return out
