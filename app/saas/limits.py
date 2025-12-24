from __future__ import annotations
import os
from datetime import date
from sqlalchemy.orm import Session
from app.saas.models import UsageDaily, User

def plan_limit(plan: str) -> int:
    plan = (plan or "FREE").upper()
    if plan == "PRO":
        return int(os.getenv("PRO_DAILY_LIMIT", "500"))
    return int(os.getenv("FREE_DAILY_LIMIT", "25"))

def get_used_today(db: Session, user: User) -> int:
    today = date.today()
    row = db.query(UsageDaily).filter(UsageDaily.user_id == user.id, UsageDaily.day == today).first()
    return row.used if row else 0

def inc_used_today(db: Session, user: User, inc: int = 1) -> int:
    today = date.today()
    row = db.query(UsageDaily).filter(UsageDaily.user_id == user.id, UsageDaily.day == today).first()
    if not row:
        row = UsageDaily(user_id=user.id, day=today, used=0)
        db.add(row)
    row.used += inc
    db.commit()
    db.refresh(row)
    return row.used
