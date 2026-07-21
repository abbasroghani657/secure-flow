from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


# ---- Auth ----
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRead(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


# ---- Targets ----
class TargetCreate(BaseModel):
    url: str
    label: Optional[str] = None


class TargetRead(BaseModel):
    id: int
    url: str
    host: str
    label: Optional[str]
    verified: bool
    verification_token: str
    verification_method: Optional[str]
    verified_at: Optional[datetime]
    created_at: datetime


class VerificationStep(BaseModel):
    method: str
    title: str
    detail: str
    value: str


class TargetDetail(TargetRead):
    instructions: list[VerificationStep]


class VerifyResult(BaseModel):
    verified: bool
    method: Optional[str] = None
    message: str


# ---- Scans ----
class ScanCreate(BaseModel):
    target_url: str
    scan_type: str = "web"
    # Optional credentials for an authenticated scan (scan behind the login).
    auth_cookie: Optional[str] = None   # raw Cookie header, e.g. "session=abc; csrf=def"
    auth_bearer: Optional[str] = None   # bearer token value (without the "Bearer " prefix)
    # Second account for BOLA/IDOR scans (scan_type == "bola").
    auth_cookie_b: Optional[str] = None
    auth_bearer_b: Optional[str] = None
    # LLM scan config (scan_type == "llm")
    llm_endpoint: Optional[str] = None
    llm_body_template: Optional[str] = None
    llm_response_path: Optional[str] = None


class CSPMScanCreate(BaseModel):
    """Read-only AWS credentials for a cloud posture scan (scan_type == 'cspm').

    Supplied by the account owner, used only for the scan, and cleared from the
    scan record the moment it finishes.
    """
    aws_access_key: str
    aws_secret_key: str
    aws_region: str = "us-east-1"
    aws_session_token: Optional[str] = None


class FindingRead(BaseModel):
    id: int
    check_id: str
    title: str
    severity: str
    url: str
    description: str
    impact: str
    evidence: str
    remediation: str
    compliance_ref: str
    passed: bool
    is_new: bool = False
    owasp: str = ""
    cwe: str = ""
    layer: str = ""


class ScanRead(BaseModel):
    id: int
    target_url: str
    scan_type: str
    status: str
    progress: int
    security_score: Optional[int]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    passed_count: int
    trigger: str = "manual"
    new_findings_count: int = 0
    authenticated: bool = False
    llm_endpoint: Optional[str] = None
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


class ScanDetail(ScanRead):
    findings: list[FindingRead]


# ---- Schedules ----
class ScheduleCreate(BaseModel):
    target_url: str
    scan_type: str = "web"
    cadence: str = "daily"  # daily | weekly
    hour_utc: int = 6
    weekday: int = 0
    alert_email: bool = True


class ScheduleUpdate(BaseModel):
    scan_type: Optional[str] = None
    cadence: Optional[str] = None
    hour_utc: Optional[int] = None
    weekday: Optional[int] = None
    enabled: Optional[bool] = None
    alert_email: Optional[bool] = None


class ScheduleRead(BaseModel):
    id: int
    target_url: str
    host: str
    scan_type: str
    cadence: str
    hour_utc: int
    weekday: int
    enabled: bool
    alert_email: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime
