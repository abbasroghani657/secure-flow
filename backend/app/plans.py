"""Plan limits and enforcement — the monetization core.

Free is deliberately useful-but-limited: real web scanning to get hooked, but the
advanced scanners, volume, scheduling and extra targets that teams need are gated
behind Pro / Business. Enforcement raises HTTP 402 (Payment Required) with an
upgrade message the frontend turns into a prompt.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlmodel import func, select

from .models import Scan, Target, User

# Every scan type the platform offers.
ALL_SCAN_TYPES = {
    "web", "deep", "headers", "llm", "mobile", "ios", "sca", "iac", "secrets",
    "cicd", "sast", "api", "container", "cspm", "bola",
}
# What Free can run — basic web surface only. Everything else is a paid upgrade.
FREE_SCAN_TYPES = {"web", "headers"}

PLAN_LIMITS = {
    "free": {
        "label": "Free", "max_targets": 1, "scans_per_month": 3,
        "scan_types": FREE_SCAN_TYPES, "scheduling": False, "teams": False,
        # Strictly limited: passive surface only, and the fixes are locked.
        "active_tests": False, "remediation": False,
        "integrations": False, "api_access": False,
    },
    "pro": {
        "label": "Pro", "max_targets": 10, "scans_per_month": 100,
        "scan_types": ALL_SCAN_TYPES, "scheduling": True, "teams": False,
        "active_tests": True, "remediation": True,
        "integrations": True, "api_access": True,
    },
    "business": {
        "label": "Business", "max_targets": None, "scans_per_month": None,
        "scan_types": ALL_SCAN_TYPES, "scheduling": True, "teams": True,
        "active_tests": True, "remediation": True,
        "integrations": True, "api_access": True,
    },
}


def plan_allows_active(plan: str) -> bool:
    """Free runs passive checks only; active injection testing is a paid feature."""
    return limits_for(plan).get("active_tests", True)


def plan_shows_remediation(plan: str) -> bool:
    """Free sees the findings but not how to fix them."""
    return limits_for(plan).get("remediation", True)


def limits_for(plan: str) -> dict:
    return PLAN_LIMITS.get(plan or "free", PLAN_LIMITS["free"])


def _month_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def scans_this_month(session, org_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(Scan)
        .where(Scan.org_id == org_id, Scan.created_at >= _month_start())
    ).one()


def target_count(session, org_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(Target).where(Target.org_id == org_id)
    ).one()


def usage_for(session, user: User) -> dict:
    lim = limits_for(user.plan)
    oid = user.current_org_id
    return {
        "plan": user.plan or "free",
        "label": lim["label"],
        "limits": {
            "max_targets": lim["max_targets"],
            "scans_per_month": lim["scans_per_month"],
            "scheduling": lim["scheduling"],
            "scan_types": sorted(lim["scan_types"]),
            "integrations": lim.get("integrations", False),
            "api_access": lim.get("api_access", False),
            "remediation": lim.get("remediation", True),
            "teams": lim.get("teams", False),
        },
        "usage": {
            "targets": target_count(session, oid) if oid else 0,
            "scans_this_month": scans_this_month(session, oid) if oid else 0,
        },
    }


def _upgrade(msg: str):
    raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, msg)


def check_can_add_target(session, user: User) -> None:
    lim = limits_for(user.plan)
    mx = lim["max_targets"]
    if mx is not None and target_count(session, user.current_org_id) >= mx:
        _upgrade(f"Your {lim['label']} plan allows {mx} target{'s' if mx != 1 else ''}. "
                 f"Upgrade to add more.")


def check_can_scan(session, user: User, scan_type: str) -> None:
    from .access import require_write
    require_write(session, user)   # viewers are read-only
    lim = limits_for(user.plan)
    if scan_type not in lim["scan_types"]:
        _upgrade(f"The '{scan_type}' scanner is a Pro feature. Upgrade to unlock all 15 scan types.")
    cap = lim["scans_per_month"]
    if cap is not None and scans_this_month(session, user.current_org_id) >= cap:
        _upgrade(f"You've used all {cap} scans on the {lim['label']} plan this month. "
                 f"Upgrade for more.")


def check_can_schedule(user: User) -> None:
    lim = limits_for(user.plan)
    if not lim["scheduling"]:
        _upgrade("Scheduled scans are a Pro feature. Upgrade to run scans automatically.")


def check_can_integrate(user: User) -> None:
    lim = limits_for(user.plan)
    if not lim.get("integrations", False):
        _upgrade("Slack, Teams and webhook alerts are a Pro feature. "
                 "Upgrade to route findings into your team's workflow.")


def check_api_access(user: User) -> None:
    lim = limits_for(user.plan)
    if not lim.get("api_access", False):
        _upgrade("API tokens and the CI/CD scanner are a Pro feature. "
                 "Upgrade to run Pentrixa in your pipeline.")


def plan_allows_teams(plan: str) -> bool:
    return limits_for(plan).get("teams", False)


def check_can_use_teams(user: User) -> None:
    if not plan_allows_teams(user.plan):
        _upgrade("Teams, roles and SSO are a Business feature. "
                 "Upgrade to invite teammates and share a workspace.")
