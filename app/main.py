import os
import json
from datetime import datetime, date
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from pydantic import BaseModel, Field

from .db import engine, Base, get_db
from .models import User, Check
from .security import (
    create_access_token,
    get_bearer_token,
    decode_token,
)
from .google_oauth import (
    build_google_auth_url,
    exchange_code_for_id_token,
    get_profile_from_id_token,
)

# =====================================================
# CONFIG
# =====================================================

APP_NAME = "Amazon Comms Compliance Checker"

ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "50"))

# =====================================================
# APP
# =====================================================

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

# =====================================================
# AUTH HELPERS
# =====================================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    token = get_bearer_token(request)
    payload = decode_token(token)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def ensure_admin_if_email(user: User) -> None:
    if ADMIN_EMAIL and user.email == ADMIN_EMAIL:
        user.role = "admin"

# =====================================================
# CHECK LOGIC
# =====================================================

PROHIBITED = [
    "whatsapp",
    "instagram",
    "facebook",
    "telegram",
    "call me",
    "email me",
    "gmail",
    "hotmail",
    "zadzwoń",
    "przelew",
    "paypal",
    "poza amazon",
]

def run_checks(message: str, proactive: bool, marketplace: str) -> dict:
    text = (message or "").lower().strip()
    hits = [w for w in PROHIBITED if w in text]

    if hits:
        return {
            "decision": "REVIEW",
            "score": max(10, 100 - 20 * len(hits)),
            "findings": hits,
            "marketplace": marketplace,
            "proactive": proactive,
        }

    return {
        "decision": "ALLOW",
        "score": 100,
        "findings": [],
        "marketplace": marketplace,
        "proactive": proactive,
    }

# =====================================================
# Pydantic MODELS
# =====================================================

class CheckRequest(BaseModel):
    marketplace: str = "DE"
    message: str
    proactive: bool = False
    days_since_completion: int = 0
    store_message: bool = False


class CheckResponse(BaseModel):
    ok: bool
    result: dict
    used_today: int
    limit_today: int
    role: str

# =====================================================
# GOOGLE OAUTH
# =====================================================

@app.get("/auth/google/start")
def google_start():
    url = build_google_auth_url(state="amz-ms")
    return RedirectResponse(url, status_code=302)


@app.get("/auth/google/callback")
async def google_callback(
    code: str,
    state: str = "",
    db: Session = Depends(get_db),
):
    # 1) Google code -> id_token
    id_token = await exchange_code_for_id_token(code)

    # 2) id_token -> profile
    profile = await get_profile_from_id_token(id_token)

    email = (profile.get("email") or "").lower().strip()
    sub = (profile.get("sub") or "").strip()

    if not email or not sub:
        raise HTTPException(status_code=401, detail="Invalid Google profile")

    # 3) upsert user
    user = db.query(User).filter(User.google_sub == sub).first()
    if not user:
        user = db.query(User).filter(User.email == email).first()

    if not user:
        user = User(
            email=email,
            google_sub=sub,
            role="user",
            plan="free",
        )
        ensure_admin_if_email(user)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        if not user.google_sub:
            user.google_sub = sub
        ensure_admin_if_email(user)
        db.commit()

    # 4) JWT
    token = create_access_token(
        sub=user.id,
        role=user.role,
    )

    # 5) back to frontend
    return RedirectResponse(f"/?token={token}", status_code=302)

# =====================================================
# LIMITS
# =====================================================

def count_used_today(db: Session, user_id: str) -> int:
    today = date.today()
    return (
        db.query(func.count(Check.id))
        .filter(Check.user_id == user_id)
        .filter(func.date(Check.created_at) == today)
        .scalar()
        or 0
    )


def enforce_limits(db: Session, user: User) -> int:
    if user.role == "admin":
        return 0

    used = count_used_today(db, user.id)
    if used >= FREE_DAILY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({FREE_DAILY_LIMIT})",
        )
    return used

# =====================================================
# CHECK ENDPOINTS
# =====================================================

@app.post("/v1/check", response_model=CheckResponse)
def demo_check(req: CheckRequest):
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="Message required")

    result = run_checks(
        req.message,
        req.proactive,
        req.marketplace,
    )

    return CheckResponse(
        ok=True,
        result=result,
        used_today=0,
        limit_today=0,
        role="demo",
    )


@app.post("/v1/checks", response_model=CheckResponse)
def user_check(
    req: CheckRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="Message required")

    used_before = enforce_limits(db, user)

    result = run_checks(
        req.message,
        req.proactive,
        req.marketplace,
    )

    preview = req.message[:500] if req.store_message else None

    chk = Check(
        user_id=user.id,
        created_at=datetime.utcnow(),
        marketplace=req.marketplace,
        proactive=req.proactive,
        days_since_completion=req.days_since_completion,
        score=result["score"],
        decision=result["decision"],
        findings_json=json.dumps(result["findings"], ensure_ascii=False),
        message_preview=preview,
    )

    db.add(chk)
    db.commit()

    used_after = used_before + (0 if user.role == "admin" else 1)
    limit = 0 if user.role == "admin" else FREE_DAILY_LIMIT

    return CheckResponse(
        ok=True,
        result=result,
        used_today=used_after,
        limit_today=limit,
        role=user.role,
    )

# =====================================================
# ADMIN
# =====================================================

@app.get("/admin/users")
def admin_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.created_at.desc()).limit(200).all()
    return {
        "items": [
            {
                "id": u.id,
                "email": u.email,
                "role": u.role,
                "plan": u.plan,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ]
    }

# =====================================================
# FRONTEND
# =====================================================

@app.get("/", response_class=HTMLResponse)
def index():
    return f"""
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8"/>
<title>{APP_NAME}</title>
</head>
<body>
<h2>{APP_NAME}</h2>
<button onclick="login()">Continue with Google</button>
<button onclick="logout()">Logout</button>
<pre id="out"></pre>

<script>
const p = new URLSearchParams(location.search);
if (p.get("token")) {{
  localStorage.setItem("token", p.get("token"));
  history.replaceState(null, "", "/");
}}

function login() {{
  location.href = "/auth/google/start";
}}
function logout() {{
  localStorage.removeItem("token");
  alert("Logged out");
}}
</script>
</body>
</html>
"""

# =====================================================
# ERRORS
# =====================================================

@app.exception_handler(HTTPException)
def http_error(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
