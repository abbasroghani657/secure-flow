from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    app_name: str = "SecureFlow"
    environment: str = "development"

    # Database
    database_url: str = "sqlite:///./secureflow.db"
    # Dev convenience: auto-create tables on startup. In production set False and
    # manage the schema with Alembic migrations (`alembic upgrade head`).
    auto_create_tables: bool = True

    # Auth
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION_use_a_long_random_string"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24  # 1 day

    # CORS — the frontend dev server
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Scanner
    max_concurrent_scans: int = 3
    scan_http_timeout: float = 12.0
    nuclei_path: str = ""  # optional: path to nuclei binary; empty = use built-in scanner only

    # Crawling + active testing (only ever run against verified targets)
    crawl_enabled: bool = True
    max_crawl_pages: int = 20
    max_crawl_depth: int = 2
    active_tests_enabled: bool = True
    max_active_urls: int = 15

    # Worker / queue
    worker_in_process: bool = True   # run the scan worker inside the API process (dev). Set False in prod and run `python -m app.worker`.
    worker_poll_seconds: float = 2.0

    # Notifications (SMTP). If smtp_host is empty, alerts are logged instead of emailed.
    alerts_enabled: bool = True
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "SecureFlow <alerts@secureflow.app>"
    smtp_starttls: bool = True
    app_base_url: str = "http://localhost:5173"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
