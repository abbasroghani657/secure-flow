import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import settings
from .database import init_db
from .middleware import SecurityHeadersMiddleware
from .ratelimit import limiter
from .routers import auth, scans, schedules, targets
from .worker import worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("secureflow")


def _check_production_secrets() -> None:
    if settings.environment == "production" and "CHANGE_ME" in settings.jwt_secret:
        raise RuntimeError(
            "JWT_SECRET is still the default in production. Set a strong secret "
            "(e.g. python -c \"import secrets;print(secrets.token_urlsafe(48))\")."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_production_secrets()
    init_db()
    if settings.worker_in_process:
        worker.start()
    yield
    worker.stop()


app = FastAPI(
    title="SecureFlow API",
    version="0.1.0",
    description="Web application security scanning platform (DAST).",
    lifespan=lifespan,
)

# Rate limiting (slowapi)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers on every response
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "app": settings.app_name, "environment": settings.environment}
