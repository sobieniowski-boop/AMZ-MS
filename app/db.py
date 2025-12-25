import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Render czasem daje URL zaczynający się od postgres://
# SQLAlchemy preferuje postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Wymuś driver psycopg (v3), żeby SQLAlchemy NIE próbował psycopg2
# Jeśli URL nie ma +driver, dodajemy +psycopg
if DATABASE_URL.startswith("postgresql://") and "postgresql+psycopg://" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass
    
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
