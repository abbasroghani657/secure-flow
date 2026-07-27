"""Social login (Google / GitHub) via the OAuth2 authorization-code flow.

Enabled only when the provider's client id + secret are configured (see
config.py). Without them the "Continue with …" buttons bounce back to the login
page with a clear, honest message instead of a broken redirect.
"""

from __future__ import annotations

import secrets as _secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlmodel import select

from ..config import settings
from ..deps import SessionDep
from ..models import User
from ..security import create_access_token, decode_access_token, hash_password

router = APIRouter(prefix="/api/auth/oauth", tags=["auth"])

_PROVIDERS = {
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
}


def _creds(provider: str) -> tuple[str, str]:
    if provider == "google":
        return settings.google_client_id, settings.google_client_secret
    if provider == "github":
        return settings.github_client_id, settings.github_client_secret
    return "", ""


def _redirect_uri(provider: str) -> str:
    return f"{settings.api_base_url}/api/auth/oauth/{provider}/callback"


def _fe(path: str) -> str:
    return f"{settings.frontend_url}{path}"


@router.get("/{provider}")
def oauth_start(provider: str):
    conf = _PROVIDERS.get(provider)
    if not conf:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider")
    cid, secret = _creds(provider)
    if not cid or not secret:
        return RedirectResponse(_fe(f"/auth?error=oauth_unconfigured&provider={provider}"))
    state = create_access_token(subject=f"oauthstate:{provider}", expires_minutes=10)
    params = {
        "client_id": cid, "redirect_uri": _redirect_uri(provider),
        "scope": conf["scope"], "response_type": "code", "state": state,
    }
    if provider == "google":
        params["prompt"] = "select_account"
    return RedirectResponse(f"{conf['authorize']}?{urlencode(params)}")


@router.get("/{provider}/callback")
def oauth_callback(provider: str, session: SessionDep, code: str = "", state: str = ""):
    conf = _PROVIDERS.get(provider)
    if not conf or not code:
        return RedirectResponse(_fe("/auth?error=oauth_failed"))
    if decode_access_token(state) != f"oauthstate:{provider}":
        return RedirectResponse(_fe("/auth?error=oauth_state"))
    cid, secret = _creds(provider)

    try:
        with httpx.Client(timeout=15, headers={"Accept": "application/json"}) as c:
            tok = c.post(conf["token"], data={
                "client_id": cid, "client_secret": secret, "code": code,
                "redirect_uri": _redirect_uri(provider), "grant_type": "authorization_code",
            }).json()
            access = tok.get("access_token")
            if not access:
                return RedirectResponse(_fe("/auth?error=oauth_token"))
            auth_h = {"Authorization": f"Bearer {access}", "Accept": "application/json"}
            ui = c.get(conf["userinfo"], headers=auth_h).json()
            email = (ui.get("email") or "").lower()
            name = ui.get("name") or ui.get("login") or (email.split("@")[0] if email else "User")
            if not email and provider == "github":
                emails = c.get("https://api.github.com/user/emails", headers=auth_h).json()
                primary = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
                email = (primary or (emails[0]["email"] if emails else "")).lower()
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return RedirectResponse(_fe("/auth?error=oauth_failed"))

    if not email:
        return RedirectResponse(_fe("/auth?error=oauth_no_email"))

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        user = User(email=email, name=str(name).strip()[:120] or "User",
                    hashed_password=hash_password(_secrets.token_urlsafe(32)))
        session.add(user)
        session.commit()
        session.refresh(user)

    token = create_access_token(subject=str(user.id))
    # Hand the token back via the URL fragment (never sent to a server / logged).
    return RedirectResponse(_fe(f"/oauth#token={token}"))
