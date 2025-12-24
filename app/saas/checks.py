from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.checker import MessageContext, check_message, load_rules
from app.saas.deps import get_db, get_current_user
from app.saas.limits import plan_limit, get_used_today, inc_used_today
from app.saas.models import Check, User
import os

router = APIRouter(prefix="/v1", tags=["checks"])

CONFIG_PATH = os.getenv("CONFIG_PATH", os.path.join(os.path.dirname(__file__), "..", "config.yaml"))

def _rules():
    # cache in module-level var
    global _RULES
    try:
        return _RULES
    except NameError:
        _RULES = load_rules(CONFIG_PATH)
        return _RULES

class PublicCheckRequest(BaseModel):
    marketplace: str = "DE"
    text: str
    is_proactive: bool = False
    days_since_order_completion: int = 0
    order_id: str | None = None

class SaasCheckRequest(BaseModel):
    marketplace: str = "DE"
    message: str
    proactive: bool = False
    days_since_completion: int = 0
    order_id: str | None = None
    message_type: str = "generic"
    store_message: bool = False

@router.post("/check")
def public_check(payload: PublicCheckRequest):
    ctx = MessageContext(
        marketplace=payload.marketplace,
        text=payload.text,
        is_proactive=payload.is_proactive,
        days_since_order_completion=payload.days_since_order_completion,
        order_id=payload.order_id,
    )
    return check_message(ctx, _rules())

@router.post("/checks")
def saas_check(
    payload: SaasCheckRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    limit = plan_limit(user.plan)
    used = get_used_today(db, user)
    if used >= limit:
        raise HTTPException(status_code=402, detail=f"Daily limit reached ({used}/{limit}). Upgrade plan.")
    # run check
    ctx = MessageContext(
        marketplace=payload.marketplace,
        text=payload.message,
        is_proactive=payload.proactive,
        days_since_order_completion=payload.days_since_completion,
        order_id=payload.order_id,
    )
    result = check_message(ctx, _rules())
    # store
    rec = Check(
        user_id=user.id,
        marketplace=payload.marketplace,
        proactive=1 if payload.proactive else 0,
        days_since_completion=payload.days_since_completion,
        order_id=payload.order_id,
        message_type=payload.message_type,
        message=payload.message if payload.store_message else None,
        result_json=json.dumps(result, ensure_ascii=False),
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    used2 = inc_used_today(db, user, 1)
    return {"check_id": rec.id, "result": result, "used": used2, "limit": limit, "plan": user.plan}
