import os
import json
from datetime import datetime, date
from typing import Optional, Any

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
import httpx
from fastapi.responses import RedirectResponse, HTMLResponse

from .db import engine, Base, get_db
from .models import User, Check
from .security import create_access_token, get_bearer_token, decode_token
from .google_oauth import build_google_auth_url, exchange_code_for_id_token, get_profile_from_id_token
import os
from datetime import datetime, timedelta
from jose import jwt

ADMIN_EMAILS = {"sobieniowski@gmail.com"}

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "10080"))  # 7 dni

def create_access_token(sub: str, role: str) -> str:
    now = datetime.utcnow()
    exp = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": sub, "role": role, "iat": int(now.timestamp()), "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

APP_NAME = "Amazon Comms Compliance Checker"
ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL", "") or "").strip().lower()
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "50"))

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


# -------------------------
# AUTH HELPERS
# -------------------------

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = get_bearer_token(request)
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def ensure_admin_if_email(user: User) -> None:
    if ADMIN_EMAIL and user.email.lower() == ADMIN_EMAIL:
        user.role = "admin"


# -------------------------
# CHECKER LOGIC (placeholder)
# -------------------------

PROHIBITED = [
    "whatsapp", "instagram", "facebook", "telegram",
    "call me", "email me", "gmail", "hotmail",
    "zadzwoń", "przelew", "paypal", "poza amazon"
]

def run_checks(message: str, proactive: bool, marketplace: str) -> dict:
    txt = (message or "").strip()
    lower = txt.lower()

    hits = [w for w in PROHIBITED if w in lower]

    if hits:
        decision = "REVIEW"
        score = max(10, 100 - 20 * len(hits))
    else:
        decision = "ALLOW"
        score = 100

    return {
        "score": score,
        "decision": decision,
        "marketplace": marketplace,
        "proactive": proactive,
        "findings": hits,
    }


# -------------------------
# API MODELS (Pydantic)
# -------------------------

from pydantic import BaseModel, Field

class CheckRequest(BaseModel):
    marketplace: str = Field("DE")
    message: str
    proactive: bool = False
    days_since_completion: int = 0
    order_id: Optional[str] = None
    store_message: bool = False  # jeśli true, zapis do historii (wymaga loginu)

class CheckResponse(BaseModel):
    ok: bool
    result: dict
    used_today: int
    limit_today: int
    role: str


# -------------------------
# GOOGLE OAUTH ENDPOINTS
# -------------------------

@app.get("/auth/google/start")
def google_start():
    # state można rozbudować (CSRF). Na MVP dajemy prosty stały.
    url = build_google_auth_url(state="amz-msg-checker")
    return RedirectResponse(url, status_code=302)


@app.get("/auth/google/callback")
async def google_callback(code: str, state: str = "", db: Session = Depends(get_db)):
    # 1) code -> id_token
    id_token = await exchange_code_for_id_token(code)
    # 2) id_token -> profile
    profile = await get_profile_from_id_token(id_token)

    email = (profile.get("email") or "").strip().lower()
    sub = (profile.get("sub") or "").strip()

    if not email or not sub:
        raise HTTPException(status_code=401, detail="Google profile missing email/sub")

    # 3) upsert user
    user = db.query(User).filter(User.google_sub == sub).first()
    if not user:
        user = db.query(User).filter(User.email == email).first()

    if not user:
        user = User(email=email, google_sub=sub, role="user", plan="free")
        ensure_admin_if_email(user)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # uzupełnij google_sub jeśli brak
        if not user.google_sub:
            user.google_sub = sub
        ensure_admin_if_email(user)
        db.commit()

    # 4) issue JWT
    token = create_access_token(user.id, user.email, user.role)

    # 5) redirect back to app with token in URL (front zapisze do localStorage)
    return RedirectResponse(url=f"/?token={token}", status_code=302)

role = "admin" if email in ADMIN_EMAILS else "user"


# -------------------------
# LIMITS
# -------------------------

def count_used_today(db: Session, user_id: str) -> int:
    today = date.today()
    # created_at >= today 00:00
    return (
        db.query(func.count(Check.id))
        .filter(Check.user_id == user_id)
        .filter(func.date(Check.created_at) == today)
        .scalar()
    ) or 0


def enforce_limits(db: Session, user: User) -> int:
    if user.role == "admin":
        return 0
    used = count_used_today(db, user.id)
    if used >= FREE_DAILY_LIMIT:
        raise HTTPException(status_code=429, detail=f"Daily limit reached ({FREE_DAILY_LIMIT})")
    return used

checks_limit = None if role == "admin" else 100

# -------------------------
# CHECK ENDPOINTS
# -------------------------

@app.post("/v1/check", response_model=CheckResponse)
def demo_check(req: CheckRequest, db: Session = Depends(get_db)):
    # demo: bez logowania, bez zapisu
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="message is required")

    result = run_checks(req.message, req.proactive, req.marketplace)
    return CheckResponse(ok=True, result=result, used_today=0, limit_today=0, role="demo")


@app.post("/v1/checks", response_model=CheckResponse)
def user_check(req: CheckRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="message is required")

    used_before = enforce_limits(db, user)

    result = run_checks(req.message, req.proactive, req.marketplace)

    # zapis checka zawsze (bo to usage); treść tylko jako preview (bezpieczniej)
    preview = req.message[:500] if req.store_message else None

    chk = Check(
        user_id=user.id,
        created_at=datetime.utcnow(),
        marketplace=req.marketplace,
        proactive=req.proactive,
        days_since_completion=int(req.days_since_completion or 0),
        score=int(result["score"]),
        decision=str(result["decision"]),
        findings_json=json.dumps(result.get("findings", []), ensure_ascii=False),
        message_preview=preview,
    )
    db.add(chk)
    db.commit()

    used_after = used_before + 1 if user.role != "admin" else 0
    limit = FREE_DAILY_LIMIT if user.role != "admin" else 0

    return CheckResponse(ok=True, result=result, used_today=used_after, limit_today=limit, role=user.role)


# -------------------------
# ADMIN (minimal)
# -------------------------

@app.get("/admin/users")
def admin_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).limit(200).all()
    return {
        "items": [
            {"id": u.id, "email": u.email, "role": u.role, "plan": u.plan, "created_at": u.created_at.isoformat()}
            for u in users
        ]
    }


# -------------------------
# FRONTEND
# -------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return f"""<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{APP_NAME}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 24px; }}
    .wrap {{ max-width: 980px; margin: 0 auto; }}
    .card {{ border:1px solid #ddd; border-radius: 10px; padding: 16px; margin: 12px 0; }}
    textarea, input, select {{ width: 100%; padding: 10px; border:1px solid #ccc; border-radius: 8px; box-sizing: border-box; }}
    textarea {{ min-height: 160px; }}
    .row {{ display:flex; gap:10px; flex-wrap: wrap; }}
    .col {{ flex:1; min-width: 220px; }}
    button {{ padding: 10px 14px; border-radius: 8px; border: 1px solid #333; background:#fff; cursor:pointer; }}
    button:hover {{ background:#f3f3f3; }}
    pre {{ background:#fafafa; border:1px solid #eee; padding: 12px; border-radius: 10px; overflow:auto; }}
    .pill {{ display:inline-block; padding: 3px 8px; border-radius:999px; border:1px solid #ddd; font-size:12px; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1 style="margin:0 0 8px 0">{APP_NAME}</h1>
  <div style="color:#555;margin-bottom:14px">
    <span class="pill">DEMO: /v1/check</span>
    <span class="pill">LOGGED: /v1/checks</span>
    <span class="pill">Admin no-limit: {ADMIN_EMAIL or "not set"}</span>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Logowanie</h3>
    <div class="row">
      <div class="col">
        <button onclick="googleLogin()">Continue with Google</button>
      </div>
      <div class="col">
        <button onclick="logout()">Logout</button>
      </div>
      <div class="col">
        <button onclick="demo()">DEMO check</button>
      </div>
    </div>
    <pre id="authOut">{{}}</pre>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Message</h3>
    <div class="row">
      <div class="col">
        <label>Marketplace</label>
        <select id="marketplace">
          <option value="DE">DE</option>
          <option value="PL">PL</option>
          <option value="FR">FR</option>
          <option value="IT">IT</option>
          <option value="ES">ES</option>
          <option value="NL">NL</option>
          <option value="SE">SE</option>
          <option value="BE">BE</option>
        </select>
      </div>
      <div class="col">
        <label>Proactive</label>
        <div style="display:flex;align-items:center;gap:8px;padding-top:8px;">
          <input id="proactive" type="checkbox" style="width:auto" />
          <span style="font-size:12px;color:#444;">Zaznacz jeśli proaktywna</span>
        </div>
      </div>
      <div class="col">
        <label>Days since completion</label>
        <input id="days" type="number" value="0" />
      </div>
      <div class="col">
        <label>Store message preview</label>
        <div style="display:flex;align-items:center;gap:8px;padding-top:8px;">
          <input id="store" type="checkbox" style="width:auto" />
          <span style="font-size:12px;color:#444;">Zapisz preview w historii</span>
        </div>
      </div>
    </div>

    <div style="margin-top:10px;">
      <label>Wiadomość</label>
      <textarea id="message" placeholder="Wklej wiadomość do klienta..."></textarea>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
      <button onclick="checkLogged()">Sprawdź (konto)</button>
      <button onclick="demo()">Sprawdź (demo)</button>
      <button onclick="clearMsg()">Wyczyść</button>
    </div>
  </div>

  <h3>Wynik</h3>
  <pre id="out">{{}}</pre>
</div>

<script>
  function setAuthOut(obj) {{
    document.getElementById("authOut").textContent = JSON.stringify(obj, null, 2);
  }}
  function setOut(obj) {{
    document.getElementById("out").textContent = JSON.stringify(obj, null, 2);
  }}

  function getToken() {{
    return localStorage.getItem("token") || "";
  }}
  function setToken(t) {{
    if (t) localStorage.setItem("token", t);
  }}
  function clearToken() {{
    localStorage.removeItem("token");
  }}

  // Jeśli wróciliśmy z Google: /?token=...
  (function initFromUrl() {{
    const url = new URL(window.location.href);
    const t = url.searchParams.get("token");
    if (t) {{
      setToken(t);
      url.searchParams.delete("token");
      window.history.replaceState({{}}, "", url.toString());
      setAuthOut({{ok:true, message:"Logged in via Google", token_saved:true}});
    }} else {{
      setAuthOut({{token_present: !!getToken()}});
    }}
  }})();

  function googleLogin() {{
    window.location.href = "/auth/google/start";
  }}

  function logout() {{
    clearToken();
    setAuthOut({{ok:true, message:"Logged out"}});
  }}

  function buildBody() {{
    return {{
      marketplace: document.getElementById("marketplace").value,
      message: document.getElementById("message").value,
      proactive: document.getElementById("proactive").checked,
      days_since_completion: Number(document.getElementById("days").value || 0),
      store_message: document.getElementById("store").checked
    }};
  }}

  async function api(path, method, body, auth) {{
    const headers = {{
      "Accept":"application/json",
      "Content-Type":"application/json"
    }};
    if (auth) {{
      const t = getToken();
      if (t) headers["Authorization"] = "Bearer " + t;
    }}
    const res = await fetch(path, {{
      method,
      headers,
      body: JSON.stringify(body)
    }});
    let data = null;
    try {{
      data = await res.json();
    }} catch(e) {{
      data = {{error:"Bad JSON", status: res.status}};
    }}
    return {{res, data}};
  }}

  async function demo() {{
    const body = buildBody();
    const {{res, data}} = await api("/v1/check", "POST", body, false);
    setOut({{status: res.status, endpoint:"/v1/check", data}});
  }}

  async function checkLogged() {{
    const body = buildBody();
    const {{res, data}} = await api("/v1/checks", "POST", body, true);
    setOut({{status: res.status, endpoint:"/v1/checks", data}});
    setAuthOut({{token_present: !!getToken()}});
  }}

  function clearMsg() {{
    document.getElementById("message").value = "";
    setOut({{}});
  }}
</script>

</body>
</html>"""


@app.exception_handler(HTTPException)
def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})