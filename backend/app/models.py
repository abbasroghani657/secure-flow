from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    hashed_password: str
    created_at: datetime = Field(default_factory=utcnow)

    targets: list["Target"] = Relationship(back_populates="owner")
    scans: list["Scan"] = Relationship(back_populates="owner")


class Target(SQLModel, table=True):
    """A website/host the user has claimed. Scans are only allowed against verified targets."""

    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id", index=True)
    url: str  # normalized origin, e.g. https://example.com
    host: str = Field(index=True)  # bare hostname, e.g. example.com
    label: Optional[str] = None
    verified: bool = Field(default=False)
    verification_token: str
    verification_method: Optional[str] = None  # dns | meta | file
    verified_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)

    owner: Optional[User] = Relationship(back_populates="targets")


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id", index=True)
    target_url: str
    scan_type: str = Field(default="web")  # web | deep | headers
    status: ScanStatus = Field(default=ScanStatus.queued, index=True)
    progress: int = Field(default=0)  # 0-100
    security_score: Optional[int] = None  # 0-100

    trigger: str = Field(default="manual")  # manual | scheduled
    schedule_id: Optional[int] = Field(default=None, foreign_key="schedule.id", index=True)
    new_findings_count: int = Field(default=0)  # issues not present in the previous scan of this target

    authenticated: bool = Field(default=False)  # was this scan run with credentials?
    # User-supplied session headers (JSON) for authenticated scanning. Sensitive:
    # cleared to NULL as soon as the scan finishes to limit exposure.
    auth_headers: Optional[str] = Field(default=None)
    # Second identity for BOLA/IDOR two-session testing (also cleared after the scan).
    auth_headers_b: Optional[str] = Field(default=None)

    # LLM scan config (scan_type == "llm")
    llm_endpoint: Optional[str] = Field(default=None)
    llm_body_template: Optional[str] = Field(default=None)  # JSON with {{PROMPT}}
    llm_response_path: Optional[str] = Field(default=None)  # dot-path into JSON response

    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    passed_count: int = Field(default=0)

    error: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    owner: Optional[User] = Relationship(back_populates="scans")
    findings: list["Finding"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)

    check_id: str  # stable slug, e.g. "missing-hsts"
    title: str
    severity: Severity
    url: str
    description: str = ""
    impact: str = ""
    evidence: str = ""
    remediation: str = ""
    # Compliance mapping, e.g. "OWASP A05:2021" / "PCI DSS 6.5"
    compliance_ref: str = ""
    # Standards taxonomy (see app/taxonomy.py)
    owasp: str = ""   # OWASP Top 10:2025 category, e.g. "A05:2025"
    cwe: str = ""     # e.g. "CWE-89"
    layer: str = ""   # frontend | api | backend | database | infra

    # Passed checks are stored as findings with severity=info and passed=True,
    # so a single table drives both the "Findings" and "Passed" tabs.
    passed: bool = Field(default=False)
    # True when this issue did not appear in the previous completed scan of the target.
    is_new: bool = Field(default=False)

    scan: Optional[Scan] = Relationship(back_populates="findings")


class Schedule(SQLModel, table=True):
    """A recurring scan for a verified target — the continuous-monitoring engine."""

    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id", index=True)
    target_url: str
    host: str
    scan_type: str = Field(default="web")
    cadence: str = Field(default="daily")  # daily | weekly
    hour_utc: int = Field(default=6)       # 0-23
    weekday: int = Field(default=0)        # 0=Mon .. 6=Sun (used for weekly)
    enabled: bool = Field(default=True)
    alert_email: bool = Field(default=True)
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utcnow)
