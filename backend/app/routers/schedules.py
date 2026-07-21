from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import Schedule, Target
from ..schemas import ScheduleCreate, ScheduleRead, ScheduleUpdate
from ..scanner.checks import normalize_url
from ..scheduling import compute_next_run

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _require_verified_target(session, owner_id: int, url: str) -> Target:
    try:
        target_url = normalize_url(url)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid target URL")
    host = urlparse(target_url).hostname
    target = session.exec(
        select(Target).where(Target.owner_id == owner_id, Target.host == host)
    ).first()
    if not target or not target.verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"'{host}' must be a verified target before you can schedule scans.",
        )
    return target


@router.post("", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
def create_schedule(data: ScheduleCreate, current: CurrentUser, session: SessionDep) -> ScheduleRead:
    target = _require_verified_target(session, current.id, data.target_url)
    schedule = Schedule(
        owner_id=current.id,
        target_url=target.url,
        host=target.host,
        scan_type=data.scan_type,
        cadence=data.cadence if data.cadence in ("daily", "weekly") else "daily",
        hour_utc=max(0, min(23, data.hour_utc)),
        weekday=max(0, min(6, data.weekday)),
        alert_email=data.alert_email,
    )
    schedule.next_run_at = compute_next_run(schedule.cadence, schedule.hour_utc, schedule.weekday)
    session.add(schedule)
    session.commit()
    session.refresh(schedule)
    return ScheduleRead.model_validate(schedule, from_attributes=True)


@router.get("", response_model=list[ScheduleRead])
def list_schedules(current: CurrentUser, session: SessionDep) -> list[ScheduleRead]:
    rows = session.exec(
        select(Schedule).where(Schedule.owner_id == current.id).order_by(Schedule.created_at.desc())
    ).all()
    return [ScheduleRead.model_validate(r, from_attributes=True) for r in rows]


@router.patch("/{schedule_id}", response_model=ScheduleRead)
def update_schedule(schedule_id: int, data: ScheduleUpdate, current: CurrentUser, session: SessionDep) -> ScheduleRead:
    sch = session.get(Schedule, schedule_id)
    if not sch or sch.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")

    fields = data.model_dump(exclude_unset=True)
    for k, v in fields.items():
        setattr(sch, k, v)
    if "hour_utc" in fields:
        sch.hour_utc = max(0, min(23, sch.hour_utc))
    if "weekday" in fields:
        sch.weekday = max(0, min(6, sch.weekday))
    if sch.cadence not in ("daily", "weekly"):
        sch.cadence = "daily"
    # Recompute the next run whenever cadence/time/enabled changes.
    if sch.enabled:
        sch.next_run_at = compute_next_run(sch.cadence, sch.hour_utc, sch.weekday)
    else:
        sch.next_run_at = None
    session.add(sch)
    session.commit()
    session.refresh(sch)
    return ScheduleRead.model_validate(sch, from_attributes=True)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: int, current: CurrentUser, session: SessionDep) -> None:
    sch = session.get(Schedule, schedule_id)
    if not sch or sch.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    session.delete(sch)
    session.commit()
