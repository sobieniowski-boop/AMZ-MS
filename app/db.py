from __future__ import annotations

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def _sqlite_url() -> str:
    # Persist to ./data on Render (mounted inside the service filesystem)
    data_dir = os.getenv("DATA_DIR", os.path.join(os.getcwd(), "data"))
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(data_dir, 'app.db')}"


def get_database_url() -> str:
    """Return a SQLAlchemy database URL.

    - If DATABASE_URL is not set -> SQLite file in ./data/app.db
    - If DATABASE_URL is Postgres (Render) -> force psycopg3 driver via postgresql+psycopg://
      This avoids psycopg2 on Python 3.13 (known import/ABI issues).
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        return _sqlite_url()

    # Render sometimes uses postgres://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]

    # Force psycopg3 driver for SQLAlchemy
    if url.startswith("postgresql://") and "+psycopg" not in url:
        url = "postgresql+psycopg://" + url[len("postgresql://") :]

    return url


class Base(DeclarativeBase):
    pass


engine = create_engine(
    get_database_url(),
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    # Ensure models are imported so metadata is complete
    from app.saas import models as _  # noqa: F401

    Base.metadata.create_all(bind=engine)
