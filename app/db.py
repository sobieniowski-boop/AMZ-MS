from __future__ import annotations
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

def _sqlite_url() -> str:
    data_dir = os.getenv("DATA_DIR", os.path.join(os.getcwd(), "data"))
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(data_dir, 'app.db')}"

def get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        return _sqlite_url()
    # Render Postgres often provides postgres:// which SQLAlchemy accepts, but psycopg prefers postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
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
    from app.saas.models import User, Check, UsageDaily  # noqa: F401
    Base.metadata.create_all(bind=engine)
