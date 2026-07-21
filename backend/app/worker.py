"""Background scan worker: a DB-backed job queue + recurring-scan scheduler.

Design
------
- A single dispatcher thread polls the DB for ``queued`` scans and hands them to a
  bounded ``ThreadPoolExecutor``. Scans are *claimed* by flipping their status to
  ``running`` before dispatch, so the next poll never double-picks them. Because
  only one thread dispatches, this is race-free within a process.
- On boot, scans left ``running`` by a previous (crashed/restarted) process are
  recovered and marked failed, so nothing is stuck forever.
- The same loop enqueues due ``Schedule`` rows, turning them into queued scans —
  this is the continuous-monitoring engine.

Deploy in-process for dev (``WORKER_IN_PROCESS=true``, started from the API's
lifespan) or as a standalone process in prod: ``python -m app.worker``.

Note: for multiple worker *processes* you would need row-level locking
(``SELECT ... FOR UPDATE``) on the claim; a single worker needs none.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sqlmodel import Session, select

from .config import settings
from .database import engine, init_db
from .models import Finding, Scan, ScanStatus, Schedule, User
from .notifications import send_scan_alert
from .scanner.engine import run_scan
from .scheduling import compute_next_run

logger = logging.getLogger("secureflow.worker")


def finalize_scan(scan_id: int) -> None:
    """After a scan completes: flag findings new vs the previous scan, then alert."""
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        if not scan or scan.status != ScanStatus.completed:
            return

        prev = s.exec(
            select(Scan)
            .where(
                Scan.owner_id == scan.owner_id,
                Scan.target_url == scan.target_url,
                Scan.status == ScanStatus.completed,
                Scan.id != scan.id,
                Scan.created_at < scan.created_at,
            )
            .order_by(Scan.created_at.desc())
        ).first()

        current = s.exec(
            select(Finding).where(Finding.scan_id == scan.id, Finding.passed == False)  # noqa: E712
        ).all()

        new_count = 0
        if prev is not None:
            prev_ids = {
                f.check_id
                for f in s.exec(
                    select(Finding).where(Finding.scan_id == prev.id, Finding.passed == False)  # noqa: E712
                ).all()
            }
            for f in current:
                if f.check_id not in prev_ids:
                    f.is_new = True
                    s.add(f)
                    new_count += 1
        # First scan of a target is the baseline: nothing is "new".

        scan.new_findings_count = new_count
        s.add(scan)
        s.commit()

        user = s.get(User, scan.owner_id)
        if user:
            try:
                send_scan_alert(scan, user.email)
            except Exception:  # noqa: BLE001
                logger.exception("alert failed for scan %s", scan_id)


class ScanWorker:
    def __init__(self) -> None:
        self.max = max(1, settings.max_concurrent_scans)
        self.executor = ThreadPoolExecutor(max_workers=self.max, thread_name_prefix="scan")
        self.inflight: set[int] = set()
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- lifecycle --
    def start(self) -> None:
        self.recover_stale()
        self._thread = threading.Thread(target=self._loop, name="scan-worker", daemon=True)
        self._thread.start()
        logger.info("Scan worker started (max_concurrent=%s)", self.max)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(settings.worker_poll_seconds):
            try:
                self.enqueue_due_schedules()
                self.dispatch()
            except Exception:  # noqa: BLE001
                logger.exception("worker loop error")

    # -- recovery --
    def recover_stale(self) -> None:
        with Session(engine) as s:
            stale = s.exec(select(Scan).where(Scan.status == ScanStatus.running)).all()
            for scan in stale:
                scan.status = ScanStatus.failed
                scan.error = "Interrupted by a server restart."
                scan.finished_at = datetime.now(timezone.utc)
                s.add(scan)
            if stale:
                s.commit()
                logger.info("recovered %d stale running scan(s)", len(stale))

    # -- dispatch --
    def dispatch(self) -> None:
        with self.lock:
            slots = self.max - len(self.inflight)
        if slots <= 0:
            return
        claimed: list[int] = []
        with Session(engine) as s:
            queued = s.exec(
                select(Scan).where(Scan.status == ScanStatus.queued).order_by(Scan.created_at).limit(slots)
            ).all()
            for scan in queued:
                with self.lock:
                    if scan.id in self.inflight or len(self.inflight) >= self.max:
                        continue
                    self.inflight.add(scan.id)
                scan.status = ScanStatus.running  # claim so the next poll skips it
                scan.started_at = datetime.now(timezone.utc)
                s.add(scan)
                claimed.append(scan.id)
            if claimed:
                s.commit()
        for sid in claimed:
            self.executor.submit(self._run, sid)

    def _run(self, scan_id: int) -> None:
        try:
            run_scan(scan_id)
            finalize_scan(scan_id)
        except Exception:  # noqa: BLE001
            logger.exception("scan %s crashed", scan_id)
        finally:
            with self.lock:
                self.inflight.discard(scan_id)

    # -- scheduler --
    def enqueue_due_schedules(self) -> None:
        now = datetime.now(timezone.utc)
        created = 0
        with Session(engine) as s:
            due = s.exec(
                select(Schedule).where(
                    Schedule.enabled == True,  # noqa: E712
                    Schedule.next_run_at != None,  # noqa: E711
                    Schedule.next_run_at <= now,
                )
            ).all()
            for sch in due:
                s.add(Scan(
                    owner_id=sch.owner_id,
                    target_url=sch.target_url,
                    scan_type=sch.scan_type,
                    status=ScanStatus.queued,
                    trigger="scheduled",
                    schedule_id=sch.id,
                ))
                sch.last_run_at = now
                sch.next_run_at = compute_next_run(sch.cadence, sch.hour_utc, sch.weekday, after=now)
                s.add(sch)
                created += 1
            if created:
                s.commit()
                logger.info("enqueued %d scheduled scan(s)", created)


# Singleton used by the API lifespan.
worker = ScanWorker()


def main() -> None:  # standalone entrypoint: python -m app.worker
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    worker.start()
    logger.info("Standalone worker running. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        worker.stop()


if __name__ == "__main__":
    main()
