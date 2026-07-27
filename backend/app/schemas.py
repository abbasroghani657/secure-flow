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
    plan: str = "free"
    current_org_id: Optional[int] = None
    created_at: datetime


class ProfileUpdate(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters")
        return v


class AccountDelete(BaseModel):
    password: str


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
    confidence: str = "firm"
    priority: int = 0
    locked: bool = False   # remediation/evidence hidden on the Free plan
    status: str = "open"   # open | false_positive | accepted | fixed


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
    resolved_count: int = 0
    authenticated: bool = False
    llm_endpoint: Optional[str] = None
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


class ScanDetail(ScanRead):
    findings: list[FindingRead]


class FindingStatusUpdate(BaseModel):
    status: str  # open | false_positive | accepted | fixed


# ---- Risk register (ASPM) ----
class RiskRow(BaseModel):
    check_id: str
    title: str
    severity: str
    priority: int = 0
    owasp: str = ""
    cwe: str = ""
    layer: str = ""
    confidence: str = "firm"
    count: int = 0
    targets: list[str] = []
    target_count: int = 0
    accepted: bool = False


class AttackStepEvidence(BaseModel):
    title: str
    target: str
    severity: str


class AttackStep(BaseModel):
    label: str
    evidence: AttackStepEvidence


class AttackPath(BaseModel):
    id: str
    title: str
    severity: str
    story: str
    steps: list[AttackStep]


class RiskOverview(BaseModel):
    targets_covered: int
    scans_considered: int
    total_risks: int
    by_severity: dict[str, int]
    risks: list[RiskRow]
    attack_paths: list[AttackPath]


# ---- Integrations ----
class IntegrationCreate(BaseModel):
    kind: str = "slack"          # slack | teams | discord | webhook
    name: str = ""
    target: str                  # incoming-webhook URL
    events: str = "critical_high"  # critical_high | new_only | all


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    events: Optional[str] = None
    enabled: Optional[bool] = None


class IntegrationRead(BaseModel):
    id: int
    kind: str
    name: str
    target: str
    events: str
    enabled: bool
    created_at: datetime
    last_fired_at: Optional[datetime]


# ---- API tokens (CLI / CI) ----
class ApiTokenCreate(BaseModel):
    name: str = ""


class ApiTokenRead(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: datetime
    last_used_at: Optional[datetime]
    revoked: bool


class ApiTokenCreated(ApiTokenRead):
    token: str  # the full secret, shown exactly once


# ---- Compliance readiness ----
class ComplianceFinding(BaseModel):
    title: str
    target: str
    severity: str
    cwe: str = ""


class ComplianceControl(BaseModel):
    id: str
    title: str
    description: str
    status: str  # met | at_risk
    issue_count: int
    findings: list[ComplianceFinding]


class ComplianceFramework(BaseModel):
    key: str
    name: str
    version: str
    blurb: str
    controls_total: int
    controls_met: int
    readiness: int
    controls: list[ComplianceControl]


class ComplianceOverview(BaseModel):
    generated_at: str
    targets_covered: int
    frameworks: list[ComplianceFramework]


# ---- Organizations / teams ----
class OrgSummary(BaseModel):
    id: int
    name: str
    role: str
    personal: bool
    member_count: int


class MemberRead(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    role: str
    joined_at: datetime


class InvitationRead(BaseModel):
    id: int
    email: EmailStr
    role: str
    status: str
    created_at: datetime


class InvitationCreated(InvitationRead):
    token: str        # shown once so the admin can copy the invite link
    accept_url: str


class OrgDetail(BaseModel):
    id: int
    name: str
    personal: bool
    my_role: str
    members: list[MemberRead]
    invitations: list[InvitationRead]


class OrgCreate(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()


class OrgRename(OrgCreate):
    pass


class InviteCreate(BaseModel):
    email: EmailStr
    role: str = "member"


class InvitePreview(BaseModel):
    org_name: str
    role: str
    email: EmailStr
    valid: bool
    reason: str = ""


class RoleUpdate(BaseModel):
    role: str


class AuditEventRead(BaseModel):
    id: int
    actor_email: str
    action: str
    detail: str
    created_at: datetime


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
