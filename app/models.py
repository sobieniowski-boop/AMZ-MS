import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)  # user/admin
    plan: Mapped[str] = mapped_column(String(20), default="free", nullable=False)
    google_sub: Mapped[str | None] = mapped_column(String(128), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    checks: Mapped[list["Check"]] = relationship(back_populates="user")


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    marketplace: Mapped[str] = mapped_column(String(10), nullable=False)
    proactive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    days_since_completion: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    decision: Mapped[str] = mapped_column(String(10), default="ALLOW", nullable=False)  # ALLOW/BLOCK/REVIEW
    findings_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)

    # opcjonalnie - nie zapisuj pełnej treści jeśli nie chcesz (compliance)
    message_preview: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship(back_populates="checks")
