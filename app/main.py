# app/main.py
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sqlite3
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# =============================================================================
# Config
# =============================================================================

APP_NAME = "Amazon Comms Compliance Checker"
DB_PATH = os.getenv("SQLITE_PATH", "app.db")

# IMPORTANT: set this in Render Environment
# e.g. AUTH_SECRET=super-long-random-string
AUTH_SECRET = os.getenv("AUTH_SECRET", "CHANGE_ME_IN_RENDER_ENV")

# Simple per-day limits
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "50"))

# Demo endpoint limit (optional)
DEMO_ENABLED = os.getenv("DEMO_ENABLED", "true").lower() in {"1", "true", "yes"}

# =============================================================================
# DB (SQLite, zero native deps, works on Render + Py3.13)
# =============================================================================


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            pass_salt TEXT NOT NULL,
            pass_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            created_at TEXT NOT NULL,
            marketplace TEXT NOT NULL,
            message TEXT NOT NULL,
            proactive INTEGER NOT NULL,
            days_since_completion INTEGER NOT NULL,
            order_id TEXT,
            result_json TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


# =============================================================================
# Auth (HMAC “JWT-like” token; no external deps)
# =============================================================================


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_token(payload: Dict[str, Any], secret: str, ttl_seconds: int = 60 * 60 * 24) -> str:
    now = int(dt.datetime.utcnow().timestamp())
    payload = dict(payload)
    payload["iat"] = now
    payload["exp"] = now + int(ttl_seconds)

    header = {"alg": "HS256", "typ": "TOKEN"}
    header_b = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    msg = f"{header_b}.{payload_b}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_b = _b64url(sig)
    return f"{header_b}.{payload_b}.{sig_b}"


def verify_token(token: str, secret: str) -> Dict[str, Any]:
    try:
        header_b, payload_b, sig_b = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")

    msg = f"{header_b}.{payload_b}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b)):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    payload = json.loads(_b64url_decode(payload_b).decode("utf-8"))
    now = int(dt.datetime.utcnow().timestamp())
    if int(payload.get("exp", 0)) < now:
        raise HTTPException(status_code=401, detail="Token expired")
    return payload


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if salt is None:
        salt = _b64url(os.urandom(16))
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        _b64url_decode(salt),
        200_000,
    )
    return salt, _b64url(dk)


def get_bearer_token(req: Request) -> str:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return auth.split(" ", 1)[1].strip()


def get_current_user(req: Request) -> sqlite3.Row:
    token = get_bearer_token(req)
    payload = verify_token(token, AUTH_SECRET)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (int(user_id),))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row


# =============================================================================
# Models
# =============================================================================


class AuthReq(BaseModel):
    email: str = Field(..., description="Email")
    password: str = Field(..., min_length=8, description="Min 8 chars")


class AuthResp(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CheckRequest(BaseModel):
    marketplace: str = Field("DE")
    message: str
    proactive: bool = False
    days_since_completion: int = 0
    order_id: Optional[str] = None
    store_message: bool = False  # UI helper (ignored for demo, used for /v1/checks)


class CheckResponse(BaseModel):
    check_id: Optional[int] = None
    result: Dict[str, Any]
    used: int
    limit: int
    plan: str


# =============================================================================
# Checker (placeholder logic; swap with your real rules/AI later)
# =============================================================================


PROHIBITED = [
    "whatsapp",
    "instagram",
    "facebook",
    "telegram",
    "zadzwoń",
    "call me",
    "write me",
    "email me",
    "gmail",
    "hotmail",
    "kontakt poza amazon",
    "poza amazon",
    "przelew",
    "paypal",
]


def run_checks(message: str, proactive: bool, marketplace: str) -> Dict[str, Any]:
    txt = (message or "").strip()
    lower = txt.lower()

    hits = [w for w in PROHIBITED if w in lower]
    ok = len(hits) == 0

    return {
        "ok": ok,
        "marketplace": marketplace,
        "proactive": proactive,
        "hits": hits,
        "summary": "OK" if ok else "Potential policy risk (external contact/payment cues).",
        "notes": [
            "This is a simplified checker. Replace run_checks() with your full rules/LLM pipeline."
        ],
    }


# =============================================================================
# Limits
# =============================================================================


def utc_day_key() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%d")


def get_usage_today(user_id: int) -> int:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) AS c FROM checks WHERE user_id=? AND substr(created_at,1,10)=?",
        (user_id, utc_day_key()),
    )
    c = int(cur.fetchone()["c"])
    conn.close()
    return c


# =============================================================================
# FastAPI app
# =============================================================================

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # if you want stricter, set your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return f"""<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{APP_NAME}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 24px; background: #fff; }}
    .wrap {{ max-width: 980px; margin: 0 auto; }}
    h1 {{ margin: 0 0 10px 0; }}
    .hint {{ color:#555; margin-bottom:16px; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin: 14px 0; }}
    label {{ display:block; font-size: 12px; color:#333; margin-bottom: 6px; }}
    input, select, textarea {{ width: 100%; padding: 10px; border:1px solid #ccc; border-radius: 8px; box-sizing: border-box; }}
    textarea {{ min-height: 160px; }}
    .row {{ display:flex; gap: 10px; flex-wrap: wrap; }}
    .col {{ flex: 1; min-width: 220px; }}
    .btns {{ display:flex; gap:10px; flex-wrap: wrap; margin-top: 10px; }}
    button {{ padding: 10px 14px; border-radius: 8px; border: 1px solid #333; background:#fff; cursor:pointer; }}
    button:hover {{ background:#f3f3f3; }}
    pre {{ background:#fafafa; border:1px solid #eee; padding: 12px; border-radius: 10px; overflow:auto; }}
    .pill {{ display:inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; border:1px solid #ddd; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>{APP_NAME}</h1>
  <div class="hint">
    <span class="pill">DEMO</span> działa bez logowania (<code>/v1/check</code>).
    Po zalogowaniu zapisuje historię i liczy limity (<code>/v1/checks</code>).
  </div>

  <div class="card">
    <h3 style="margin-top:0">Login / Signup</h3>
    <div class="row">
      <div class="col">
        <label>Email</label>
        <input id="email" placeholder="email" />
      </div>
      <div class="col">
        <label>Password (min 8 znaków)</label>
        <input id="password" type="password" placeholder="min 8 znaków" />
      </div>
    </div>
    <div class="btns">
      <button onclick="signup()">Sign up</button>
      <button onclick="login()">Login</button>
      <button onclick="logout()">Logout</button>
      <button onclick="demo()">DEMO</button>
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
        <div style="display:flex; align-items:center; gap:8px; padding-top:8px;">
          <input id="proactive" type="checkbox" style="width:auto" />
          <span style="font-size:12px;color:#444;">Zaznacz jeśli wiadomość proaktywna</span>
        </div>
      </div>
      <div class="col">
        <label>Days since completion</label>
        <input id="days" type="number" value="0" />
      </div>
      <div class="col">
        <label>Order ID (opcjonalnie)</label>
        <input id="orderId" placeholder="opcjonalnie" />
      </div>
      <div class="col">
        <label>Store message</label>
        <div style="display:flex; align-items:center; gap:8px; padding-top:8px;">
          <input id="store" type="checkbox" style="width:auto" />
          <span style="font-size:12px;color:#444;">Zapisz w historii (wymaga logowania)</span>
        </div>
      </div>
    </div>

    <div style="margin-top:10px;">
      <label>Wiadomość</label>
      <textarea id="message" placeholder="Wklej wiadomość do klienta..."></textarea>
    </div>

    <div class="btns">
      <button onclick="check()">Sprawdź</button>
      <button onclick="clearMsg()">Wyczyść</button>
    </div>
  </div>

  <h3>Wynik</h3>
  <pre id="out">{{}}</pre>
</div>

<script>
  const API_BASE = "";

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

  async function api(path, method="GET", body=null) {{
    const headers = {{"Accept":"application/json"}};
    if (body) headers["Content-Type"] = "application/json";
    const t = getToken();
    if (t) headers["Authorization"] = "Bearer " + t;

    const res = await fetch(API_BASE + path, {{
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    }});

    let data = null;
    try {{
      data = await res.json();
    }} catch (e) {{
      data = {{ error: "Bad JSON", status: res.status }};
    }}
    return {{ res, data }};
  }}

  async function signup() {{
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const {{res, data}} = await api("/auth/signup", "POST", {{email, password}});
    setAuthOut({{status: res.status, data}});
  }}

  async function login() {{
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const {{res, data}} = await api("/auth/login", "POST", {{email, password}});
    if (res.ok && data.access_token) setToken(data.access_token);
    setAuthOut({{status: res.status, data}});
  }}

  function logout() {{
    clearToken();
    setAuthOut({{ok:true, message:"Logged out"}});
  }}

  async function demo() {{
    const body = buildBody();
    const {{res, data}} = await api("/v1/check", "POST", body);
    setOut({{status: res.status, endpoint:"/v1/check", data}});
  }}

  function buildBody() {{
    // ✅ NAJWAŻNIEJSZE: klucze muszą pasować do backendu
    const marketplace = document.getElementById("marketplace").value;
    const message = document.getElementById("message").value;
    const proactive = document.getElementById("proactive").checked;
    const days = Number(document.getElementById("days").value || 0);
    const orderId = document.getElementById("orderId").value.trim();
    const store = document.getElementById("store").checked;

    return {{
      marketplace: marketplace,
      message: message,
      proactive: proactive,
      days_since_completion: days,
      order_id: orderId ? orderId : null,
      store_message: store
    }};
  }}

  async function check() {{
    const body = buildBody();
    // jeśli user zaznaczył "store message", próbujemy /v1/checks (auth + limity)
    // jeśli nie, robimy demo /v1/check
    const endpoint = body.store_message ? "/v1/checks" : "/v1/check";
    const {{res, data}} = await api(endpoint, "POST", body);
    setOut({{status: res.status, endpoint, data}});
  }}

  function clearMsg() {{
    document.getElementById("message").value = "";
    setOut({{}});
  }}
</script>
</body>
</html>"""


# =============================================================================
# Auth routes
# =============================================================================

@app.post("/auth/signup", response_model=AuthResp)
def signup(req: AuthReq):
    email = req.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Invalid email")

    salt, ph = hash_password(req.password)

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(email, pass_salt, pass_hash, created_at) VALUES(?,?,?,?)",
            (email, salt, ph, dt.datetime.utcnow().isoformat()),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Email already exists")
    conn.close()

    token = make_token({"sub": str(user_id), "email": email}, AUTH_SECRET)
    return AuthResp(access_token=token)


@app.post("/auth/login", response_model=AuthResp)
def login(req: AuthReq):
    email = req.email.strip().lower()

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    salt = row["pass_salt"]
    _, ph = hash_password(req.password, salt=salt)
    if ph != row["pass_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = make_token({"sub": str(row["id"]), "email": email}, AUTH_SECRET)
    return AuthResp(access_token=token)


# =============================================================================
# API routes
# =============================================================================

@app.post("/v1/check", response_model=CheckResponse)
def check_demo(req: CheckRequest):
    if not DEMO_ENABLED:
        raise HTTPException(status_code=403, detail="Demo disabled")

    if not req.message or not req.message.strip():
        raise HTTPException(status_code=422, detail="message is required")

    result = run_checks(req.message, req.proactive, req.marketplace)
    # demo: no user, no persistence, no limits
    return CheckResponse(check_id=None, result=result, used=0, limit=0, plan="demo")


@app.post("/v1/checks", response_model=CheckResponse)
def check_paid(req: CheckRequest, user=Depends(get_current_user)):
    if not req.message or not req.message.strip():
        raise HTTPException(status_code=422, detail="message is required")

    user_id = int(user["id"])
    used = get_usage_today(user_id)
    if used >= FREE_DAILY_LIMIT:
        raise HTTPException(status_code=429, detail=f"Daily limit reached ({FREE_DAILY_LIMIT})")

    result = run_checks(req.message, req.proactive, req.marketplace)

    created_at = dt.datetime.utcnow().isoformat()
    to_store_message = req.message if req.store_message else "[NOT STORED]"

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO checks(user_id, created_at, marketplace, message, proactive, days_since_completion, order_id, result_json)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            user_id,
            created_at,
            req.marketplace,
            to_store_message,
            1 if req.proactive else 0,
            int(req.days_since_completion or 0),
            req.order_id,
            json.dumps(result, ensure_ascii=False),
        ),
    )
    conn.commit()
    check_id = cur.lastrowid
    conn.close()

    used_after = used + 1
    return CheckResponse(
        check_id=check_id,
        result=result,
        used=used_after,
        limit=FREE_DAILY_LIMIT,
        plan="free",
    )


@app.get("/v1/history")
def history(limit: int = 50, user=Depends(get_current_user)):
    user_id = int(user["id"])
    limit = max(1, min(int(limit), 200))

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, created_at, marketplace, proactive, days_since_completion, order_id, message, result_json
        FROM checks
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user_id, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    for r in rows:
        try:
            r["result"] = json.loads(r.pop("result_json"))
        except Exception:
            r["result"] = {}
    return {"items": rows, "count": len(rows)}


# =============================================================================
# Error handler (nicer JSON)
# =============================================================================

@app.exception_handler(HTTPException)
def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
```0