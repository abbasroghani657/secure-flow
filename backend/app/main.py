import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .config import settings
from .database import init_db
from .middleware import SecurityHeadersMiddleware
from .ratelimit import limiter
from .routers import admin, auth, billing, compliance, integrations, oauth, orgs, risk, scans, schedules, targets, tokens
from .worker import worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("pentrixa")


def _check_production_secrets() -> None:
    if settings.environment == "production" and "CHANGE_ME" in settings.jwt_secret:
        raise RuntimeError(
            "JWT_SECRET is still the default in production. Set a strong secret "
            "(e.g. python -c \"import secrets;print(secrets.token_urlsafe(48))\")."
        )


def _init_sentry() -> None:
    """Wire up error tracking when a DSN is configured. No-op otherwise, and a
    missing sentry-sdk never breaks boot, it's an optional prod dependency."""
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk  # type: ignore

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.environment,
            traces_sample_rate=settings.sentry_traces_sample_rate,
        )
        logger.info("Sentry error tracking enabled")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Sentry not initialised (%s). Install sentry-sdk to enable.", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_production_secrets()
    _init_sentry()
    init_db()
    if settings.worker_in_process:
        worker.start()
    yield
    worker.stop()


app = FastAPI(
    title="Pentrixa API",
    version="0.1.0",
    description="Web application security scanning platform (DAST).",
    lifespan=lifespan,
)

# Rate limiting (slowapi)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers on every response
app.add_middleware(SecurityHeadersMiddleware)

# Trust reverse-proxy headers (like X-Forwarded-For) so the rate limiter bans the actual client IP, not the load balancer.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(billing.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)
app.include_router(integrations.router)
app.include_router(tokens.router)
app.include_router(risk.router)
app.include_router(orgs.router)
app.include_router(compliance.router)
app.include_router(admin.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "app": settings.app_name, "environment": settings.environment}


@app.get("/api/health/ready", tags=["meta"])
def readiness():
    """Deep check for load balancers and orchestrators: is the DB reachable?"""
    from sqlalchemy import text
    from .database import engine

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as exc:  # noqa: BLE001
        logger.warning("readiness check failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "database": "unreachable"},
        )


@app.get("/.well-known/security.txt", include_in_schema=False)
def security_txt() -> PlainTextResponse:
    """Our own responsible-disclosure contact — the trust signal we tell
    customers to publish, published for ourselves."""
    base = settings.app_base_url.rstrip("/")
    body = (
        f"Contact: mailto:security@pentrixa.app\n"
        f"Policy: {base}/security\n"
        f"Preferred-Languages: en\n"
        f"Canonical: {base}/.well-known/security.txt\n"
    )
    return PlainTextResponse(body, media_type="text/plain")


# SUPREME-TIER HONEYPOT TRAPS
HONEYPOT_PATHS = ["/.env", "/wp-login.php", "/wp-admin", "/phpinfo.php", "/config.json", "/.git/config"]

from fastapi import Request
from .models import HoneypotHit
from .database import get_session
from sqlmodel import Session

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"], include_in_schema=False)
async def honeypot_catch_all(request: Request, path: str):
    """Catch-all for malicious bots probing the root."""
    target_path = f"/{path}"
    
    # Check if the path looks like an attack (it's in our known honeypot list)
    if any(target_path.startswith(p) for p in HONEYPOT_PATHS):
        try:
            from .database import engine
            with Session(engine) as session:
                hit = HoneypotHit(
                    honeypot_url=target_path,
                    ip_address=request.client.host if request.client else "unknown",
                    headers=str(request.headers.items())
                )
                session.add(hit)
                session.commit()
                # Also log to Audit events for the firehose
                from .models import AuditEvent
                evt = AuditEvent(
                    org_id=1,  # Global org fallback
                    actor_email="anonymous-bot",
                    action="HONEYPOT_TRIGGERED",
                    detail=f"Malicious probe detected from {hit.ip_address} on {target_path}"
                )
                session.add(evt)
                session.commit()
        except Exception as e:
            logger.error(f"Honeypot logging failed: {e}")
            
    # Return a generic 404 regardless to avoid fingerprinting
    return JSONResponse(status_code=404, content={"detail": "Not Found"})
