from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine

from .config import settings

_is_sqlite = settings.database_url.startswith("sqlite")

# SQLite (dev) needs check_same_thread off for the threaded worker. Postgres
# (prod) gets pool_pre_ping so a connection dropped by the server is detected
# and replaced instead of raising, plus a recycle window and a real pool.
if _is_sqlite:
    engine = create_engine(
        settings.database_url, echo=False,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        settings.database_url, echo=False,
        pool_pre_ping=True,
        pool_recycle=settings.db_pool_recycle,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
    )


def init_db() -> None:
    # Import models so SQLModel registers the tables before create_all.
    from . import models  # noqa: F401

    # In production the schema is owned by Alembic migrations; skip auto-create.
    if settings.auto_create_tables:
        SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
