import json
import os
from urllib.parse import urlparse

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from sqlmodel import select

from ..config import settings
from ..deps import CurrentUser, SessionDep
from ..models import Finding, Scan, ScanStatus, Target
from ..schemas import FindingRead, ScanCreate, ScanDetail, ScanRead
from ..scanner.checks import normalize_url

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _scan_read(scan: Scan) -> ScanRead:
    return ScanRead.model_validate(scan, from_attributes=True)


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    data: ScanCreate,
    current: CurrentUser,
    session: SessionDep,
) -> ScanRead:
    # For an LLM scan the "target" is the LLM endpoint; otherwise it's the URL.
    if data.scan_type == "llm":
        if not data.llm_endpoint:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "An LLM endpoint URL is required.")
        endpoint = data.llm_endpoint.strip()
        parsed = urlparse(endpoint if "://" in endpoint else "https://" + endpoint)
        host = parsed.hostname
        if not host:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Could not parse a host from the LLM endpoint.")
        target_url = endpoint
    else:
        try:
            target_url = normalize_url(data.target_url)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid target URL")
        host = urlparse(target_url).hostname

    target = session.exec(
        select(Target).where(Target.owner_id == current.id, Target.host == host)
    ).first()
    if not target:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"'{host}' is not one of your targets. Add and verify it first.",
        )
    if not target.verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"'{host}' is not verified yet. Prove ownership before scanning.",
        )

    # Optional credentials for an authenticated scan (or LLM API auth headers).
    def _build_headers(cookie: str | None, bearer: str | None) -> dict[str, str]:
        h: dict[str, str] = {}
        if cookie:
            h["Cookie"] = cookie.strip()
        if bearer:
            h["Authorization"] = f"Bearer {bearer.strip()}"
        return h

    auth_headers = _build_headers(data.auth_cookie, data.auth_bearer)
    auth_headers_b = _build_headers(data.auth_cookie_b, data.auth_bearer_b)

    if data.scan_type == "bola" and not (auth_headers and auth_headers_b):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A BOLA/IDOR scan needs credentials for TWO different accounts (A and B).",
        )

    scan = Scan(
        owner_id=current.id, target_url=target_url, scan_type=data.scan_type,
        status=ScanStatus.queued,
        authenticated=bool(auth_headers),
        auth_headers=json.dumps(auth_headers) if auth_headers else None,
        auth_headers_b=json.dumps(auth_headers_b) if auth_headers_b else None,
        llm_endpoint=data.llm_endpoint.strip() if data.scan_type == "llm" and data.llm_endpoint else None,
        llm_body_template=data.llm_body_template if data.scan_type == "llm" else None,
        llm_response_path=data.llm_response_path if data.scan_type == "llm" else None,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # The background worker picks up queued scans; no request-bound task.
    return _scan_read(scan)


@router.post("/mobile", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_mobile_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload an Android APK for static analysis (OWASP Mobile Top 10)."""
    filename = file.filename or "app.apk"
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Please upload an .apk file.")
    data = await file.read()
    if len(data) > settings.max_apk_mb * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"APK too large (max {settings.max_apk_mb} MB).")
    if data[:2] != b"PK":  # APKs are ZIP archives
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That file is not a valid APK.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="mobile", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.apk"), "wb") as fh:
        fh.write(data)

    return _scan_read(scan)


@router.post("/ios", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_ios_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload an iOS IPA for static analysis (OWASP Mobile Top 10)."""
    filename = file.filename or "app.ipa"
    if not filename.lower().endswith(".ipa"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Please upload an .ipa file.")
    data = await file.read()
    if len(data) > settings.max_apk_mb * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"IPA too large (max {settings.max_apk_mb} MB).")
    if data[:2] != b"PK":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That file is not a valid IPA.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="ios", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.ipa"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.post("/sca", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_sca_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload a dependency manifest (package.json / requirements.txt / go.mod / lock file)."""
    filename = file.filename or "manifest.txt"
    data = await file.read()
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Manifest too large (max 5 MB).")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That does not look like a text manifest.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="sca", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.dep"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.post("/iac", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_iac_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload an IaC file (Terraform / CloudFormation / Kubernetes / Dockerfile / compose)."""
    filename = file.filename or "main.tf"
    data = await file.read()
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "IaC file too large (max 5 MB).")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That does not look like a text IaC file.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="iac", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.iac"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.post("/secrets", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_secrets_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload a source archive (.zip) or a single text file to scan for leaked secrets."""
    filename = file.filename or "source.zip"
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Archive too large (max 20 MB).")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The uploaded file is empty.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="secrets", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.src"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.post("/cicd", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_cicd_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload a CI/CD workflow (GitHub Actions / GitLab CI) or a .zip of them."""
    filename = file.filename or "workflow.yml"
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File too large (max 10 MB).")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The uploaded file is empty.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="cicd", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.ci"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.post("/sast", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_sast_scan(
    current: CurrentUser,
    session: SessionDep,
    file: UploadFile = File(...),
) -> ScanRead:
    """Upload a source archive (.zip) or a single file for static code analysis (SAST)."""
    filename = file.filename or "source.zip"
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Archive too large (max 20 MB).")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The uploaded file is empty.")

    scan = Scan(owner_id=current.id, target_url=filename, scan_type="sast", status=ScanStatus.queued)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(os.path.join(settings.upload_dir, f"{scan.id}.sast"), "wb") as fh:
        fh.write(data)
    return _scan_read(scan)


@router.get("", response_model=list[ScanRead])
def list_scans(current: CurrentUser, session: SessionDep) -> list[ScanRead]:
    scans = session.exec(
        select(Scan).where(Scan.owner_id == current.id).order_by(Scan.created_at.desc())
    ).all()
    return [_scan_read(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, current: CurrentUser, session: SessionDep) -> ScanDetail:
    scan = session.get(Scan, scan_id)
    if not scan or scan.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
    ).all()
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: (f.passed, severity_rank.get(f.severity, 5)))
    detail = ScanDetail.model_validate(scan, from_attributes=True)
    detail.findings = [FindingRead.model_validate(f, from_attributes=True) for f in findings_sorted]
    return detail


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, current: CurrentUser, session: SessionDep) -> None:
    scan = session.get(Scan, scan_id)
    if not scan or scan.owner_id != current.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    session.delete(scan)
    session.commit()
