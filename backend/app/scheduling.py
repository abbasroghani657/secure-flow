"""Pure helpers for computing when a schedule should next run (UTC)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def compute_next_run(cadence: str, hour_utc: int, weekday: int, after: datetime | None = None) -> datetime:
    """Next UTC datetime strictly after ``after`` matching the cadence.

    - daily:  the next day where the time is hour_utc:00
    - weekly: the next occurrence of ``weekday`` (0=Mon) at hour_utc:00
    """
    now = after or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    hour_utc = max(0, min(23, hour_utc))
    candidate = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)

    if cadence == "weekly":
        weekday = max(0, min(6, weekday))
        days_ahead = (weekday - candidate.weekday()) % 7
        candidate = candidate + timedelta(days=days_ahead)
        if candidate <= now:
            candidate = candidate + timedelta(days=7)
        return candidate

    # daily
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate
