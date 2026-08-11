import hashlib
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from ..access import ensure_personal_org
from ..deps import CurrentUser, SessionDep
from ..models import (
    ApiToken, Integration, Membership, Organization, Scan, Schedule, Target, User, VerificationToken
)
from ..notifications import send_password_changed_notice, send_password_reset_email, send_verification_email
from ..ratelimit import limiter
from ..schemas import (
    AccountDelete, ForgotPasswordRequest, PasswordChange, ProfileUpdate, ResetPasswordRequest,
    TokenResponse, UserCreate, UserLogin, UserRead, VerifyEmailRequest
)
from ..security import create_access_token, hash_password, verify_password

# Mitigate timing attacks during login (username enumeration)
DUMMY_HASH = hash_password("dummy_password_for_timing_mitigation")

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _token_response(user: User) -> TokenResponse:
    token = create_access_token(subject=str(user.id), token_version=user.token_version)
    return TokenResponse(
        access_token=token,
        user=UserRead(id=user.id, name=user.name, email=user.email, plan=user.plan, current_org_id=user.current_org_id, created_at=user.created_at),
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, data: UserCreate, session: SessionDep, bg_tasks: BackgroundTasks) -> TokenResponse:
    email = data.email.lower()
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    user = User(
        email=email,
        name=data.name.strip(),
        hashed_password=hash_password(data.password),
    )
    session.add(user)
    session.flush()  # Apex-Tier: Flush to get user.id without committing the transaction!
    
    # ensure_personal_org will now use flush() instead of commit()
    ensure_personal_org(session, user)
    
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    v_token = VerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        purpose="email_verify",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        request_ip=request.client.host if request.client else ""
    )
    session.add(v_token)
    
    session.commit()  # Single atomic commit for User, Org, Membership, and Token!
    session.refresh(user)
    
    bg_tasks.add_task(send_verification_email, email, raw_token)
    
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, data: UserLogin, session: SessionDep) -> TokenResponse:
    user = session.exec(select(User).where(User.email == data.email.lower())).first()
    if not user:
        verify_password(data.password, DUMMY_HASH)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
        
    if not verify_password(data.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
        
    if user.is_locked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is securely locked. Check your email for unlock instructions or contact support.")
        
    return _token_response(user)


@router.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
def login_form(request: Request, form: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep) -> TokenResponse:
    """OAuth2 password flow — lets the interactive /docs 'Authorize' button work."""
    user = session.exec(select(User).where(User.email == form.username.lower())).first()
    if not user:
        verify_password(form.password, DUMMY_HASH)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
        
    if not verify_password(form.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
        
    if user.is_locked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is securely locked.")
        
    return _token_response(user)


@router.get("/me", response_model=UserRead)
def me(current: CurrentUser) -> UserRead:
    return UserRead(id=current.id, name=current.name, email=current.email, plan=current.plan, current_org_id=current.current_org_id, created_at=current.created_at)


@router.patch("/me", response_model=UserRead)
def update_profile(data: ProfileUpdate, current: CurrentUser, session: SessionDep) -> UserRead:
    current.name = data.name
    session.add(current)
    session.commit()
    session.refresh(current)
    return UserRead(id=current.id, name=current.name, email=current.email, plan=current.plan, current_org_id=current.current_org_id, created_at=current.created_at)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(data: PasswordChange, current: CurrentUser, session: SessionDep) -> None:
    if not verify_password(data.current_password, current.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    current.hashed_password = hash_password(data.new_password)
    current.token_version += 1  # Apex-Tier: Revoke all active sessions upon password change
    session.add(current)
    session.commit()


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(data: AccountDelete, current: CurrentUser, session: SessionDep) -> None:
    """Permanently delete the account and everything owned by it. Password-gated."""
    if not verify_password(data.password, current.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password is incorrect")
    uid = current.id
    # Remove owned data first (scans cascade their findings via the relationship).
    for scan in session.exec(select(Scan).where(Scan.owner_id == uid)).all():
        session.delete(scan)
    for model in (Target, Schedule, Integration, ApiToken):
        for row in session.exec(select(model).where(model.owner_id == uid)).all():
            session.delete(row)
    for v_token in session.exec(select(VerificationToken).where(VerificationToken.user_id == uid)).all():
        session.delete(v_token)
    # Drop their team memberships and any personal workspaces they own.
    for mem in session.exec(select(Membership).where(Membership.user_id == uid)).all():
        session.delete(mem)
    for org in session.exec(
        select(Organization).where(Organization.created_by_id == uid, Organization.personal == True)  # noqa: E712
    ).all():
        session.delete(org)
    session.delete(current)
    session.commit()


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5/minute")
def verify_email(request: Request, data: VerifyEmailRequest, session: SessionDep) -> None:
    token_hash = hashlib.sha256(data.token.encode()).hexdigest()
    v_token = session.exec(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.purpose == "email_verify"
        )
    ).first()
    
    if not v_token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
        
    expires = v_token.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
        
    if expires < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
        
    user = session.get(User, v_token.user_id)
    if not user:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid token")
        
    user.email_verified = True
    if user.pending_email:
        user.email = user.pending_email
        user.pending_email = None
        
    session.add(user)
    session.delete(v_token)
    session.commit()


@router.post("/resend-verification", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("3/hour") 
def resend_verification(request: Request, current: CurrentUser, session: SessionDep, bg_tasks: BackgroundTasks) -> None:
    if current.email_verified and not current.pending_email:
        return
        
    now = datetime.now(timezone.utc)
    if current.last_verify_requested_at:
        last_req = current.last_verify_requested_at
        if last_req.tzinfo is None:
            last_req = last_req.replace(tzinfo=timezone.utc)
        if (now - last_req).total_seconds() < 180:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Please wait before requesting another email")
        
    for t in session.exec(select(VerificationToken).where(VerificationToken.user_id == current.id, VerificationToken.purpose == "email_verify")).all():
        session.delete(t)
        
    current.last_verify_requested_at = now
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    v_token = VerificationToken(
        user_id=current.id,
        token_hash=token_hash,
        purpose="email_verify",
        expires_at=now + timedelta(days=7),
        request_ip=request.client.host if request.client else ""
    )
    session.add(v_token)
    session.add(current)
    session.commit()
    
    email = current.pending_email or current.email
    bg_tasks.add_task(send_verification_email, email, raw_token)


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("50/minute") 
def forgot_password(request: Request, data: ForgotPasswordRequest, session: SessionDep, bg_tasks: BackgroundTasks) -> None:
    start_time = time.time()
    
    email = data.email.lower()
    user = session.exec(select(User).where(User.email == email)).first()
    now = datetime.now(timezone.utc)
    
    if user:
        last_req = user.last_reset_requested_at
        if last_req and last_req.tzinfo is None:
            last_req = last_req.replace(tzinfo=timezone.utc)
            
        if not last_req or (now - last_req).total_seconds() >= 180:
            for t in session.exec(select(VerificationToken).where(VerificationToken.user_id == user.id, VerificationToken.purpose == "password_reset")).all():
                session.delete(t)
                
            user.last_reset_requested_at = now
            raw_token = secrets.token_urlsafe(64)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            
            v_token = VerificationToken(
                user_id=user.id,
                token_hash=token_hash,
                purpose="password_reset",
                expires_at=now + timedelta(hours=1),
                request_ip=request.client.host if request.client else ""
            )
            session.add(v_token)
            session.add(user)
            session.commit()
            
            bg_tasks.add_task(send_password_reset_email, email, raw_token)
            
    elapsed = time.time() - start_time
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)
        

@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
def reset_password(request: Request, data: ResetPasswordRequest, session: SessionDep, bg_tasks: BackgroundTasks) -> None:
    token_hash = hashlib.sha256(data.token.encode()).hexdigest()
    
    v_token = session.exec(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.purpose == "password_reset"
        )
    ).first()
    
    if not v_token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
        
    expires = v_token.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
        
    if expires < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
        
    user = session.get(User, v_token.user_id)
    if not user:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid token")
        
    user.hashed_password = hash_password(data.new_password)
    user.token_version += 1
    user.is_locked = False
    
    freeze_raw = secrets.token_urlsafe(64)
    freeze_hash = hashlib.sha256(freeze_raw.encode()).hexdigest()
    freeze_token = VerificationToken(
        user_id=user.id,
        token_hash=freeze_hash,
        purpose="account_freeze",
        expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        request_ip=request.client.host if request.client else ""
    )
    
    session.add(freeze_token)
    session.add(user)
    session.delete(v_token)
    session.commit()
    
    bg_tasks.add_task(send_password_changed_notice, user.email, freeze_raw)


@router.get("/freeze-account")
def freeze_account(request: Request, token: str, session: SessionDep) -> dict:
    """1-Click killswitch if the user didn't authorize the password reset."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    v_token = session.exec(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.purpose == "account_freeze"
        )
    ).first()
    
    if not v_token:
        return {"msg": "If the token was valid, the account has been frozen."}
        
    user = session.get(User, v_token.user_id)
    if user:
        user.is_locked = True
        user.token_version += 1 
        session.add(user)
        session.delete(v_token)
        session.commit()
        
    return {"msg": "Your account has been securely locked."}
