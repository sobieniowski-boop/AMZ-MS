from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import time
import os
import hashlib
import jwt

# =========================
# CONFIG
# =========================

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
JWT_ALG = "HS256"

DEMO_LIMIT = 5
USER_LIMIT = 100

# =========================
# APP INIT
# =========================

app = FastAPI(title="Amazon Comms Compliance Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# =========================
# IN-MEMORY STORAGE (MVP)
# =========================

USERS = {}
TOKENS = {}
CHECKS = []

# =========================
# UTILS
# =========================

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "iat": int(time.time())
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)
    TOKENS[token] = email
    return token

def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if email not in USERS:
            raise HTTPException(status_code=401, detail="Invalid user")
        return email
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# =========================
# MODELS
# =========================

class AuthIn(BaseModel):
    email: str
    password: str

class CheckIn(BaseModel):
    marketplace: str
    text: str
    is_proactive: bool = False
    days_since_order_completion: int = 0
    order_id: Optional[str] = None
    store_message: bool = False

class CheckOut(BaseModel):
    compliant: bool
    issues: List[str]

# =========================
# BUSINESS LOGIC
# =========================

def analyze_message(data: CheckIn) -> CheckOut:
    issues = []

    if "refund" in data.text.lower() and data.is_proactive:
        issues.append("Refund mentioned in proactive message")

    if data.days_since_order_completion > 30:
        issues.append("Message sent too long after order completion")

    compliant = len(issues) == 0
    return CheckOut(compliant=compliant, issues=issues)

# =========================
# AUTH ENDPOINTS
# =========================

@app.post("/auth/signup")
def signup(data: AuthIn):
    if data.email in USERS:
        raise HTTPException(status_code=400, detail="User exists")
    USERS[data.email] = {
        "password": hash_password(data.password),
        "created": time.time(),
        "checks": 0
    }
    return {"status": "ok"}

@app.post("/auth/login")
def login(data: AuthIn):
    user = USERS.get(data.email)
    if not user or user["password"] != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(data.email)
    return {"access_token": token}

# =========================
# CHECK ENDPOINTS
# =========================

@app.post("/v1/check", response_model=CheckOut)
def demo_check(data: CheckIn):
    if len(CHECKS) >= DEMO_LIMIT:
        raise HTTPException(status_code=429, detail="Demo limit reached")
    result = analyze_message(data)
    CHECKS.append({
        "user": "demo",
        "data": data.dict(),
        "result": result.dict()
    })
    return result

@app.post("/v1/checks", response_model=CheckOut)
def user_check(data: CheckIn, user: str = Depends(get_current_user)):
    USERS[user]["checks"] += 1
    if USERS[user]["checks"] > USER_LIMIT:
        raise HTTPException(status_code=429, detail="User limit reached")

    result = analyze_message(data)

    if data.store_message:
        CHECKS.append({
            "user": user,
            "data": data.dict(),
            "result": result.dict()
        })

    return result

# =========================
# FRONTEND (SINGLE FILE)
# =========================

HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Amazon Comms Compliance Checker</title>
<style>
body { font-family: Arial; margin: 40px; }
textarea { width: 100%; height: 120px; }
input, select { margin: 4px; }
pre { background: #f4f4f4; padding: 10px; }
</style>
</head>
<body>

<h2>Amazon Comms Compliance Checker</h2>

<h3>Login / Signup</h3>
<input id="email" placeholder="email">
<input id="password" type="password" placeholder="min 8 znaków">
<button onclick="signup()">Sign up</button>
<button onclick="login()">Login</button>
<button onclick="logout()">Logout</button>
<button onclick="setDemo()">DEMO</button>
<pre id="auth"></pre>

<h3>Message</h3>
<select id="marketplace">
  <option value="DE">DE</option>
  <option value="PL">PL</option>
</select>
<label><input type="checkbox" id="proactive"> Proactive</label><br>
Days since completion: <input id="days" value="0"><br>
Order ID: <input id="order"><br>
<label><input type="checkbox" id="store"> Store message</label><br>
<textarea id="text" placeholder="Wklej wiadomość do klienta..."></textarea><br>
<button onclick="check()">Sprawdź</button>
<button onclick="clearAll()">Wyczyść</button>

<h3>Wynik</h3>
<pre id="result"></pre>

<script>
let TOKEN = null;
let DEMO = false;

function setDemo() {
  TOKEN = null;
  DEMO = true;
  document.getElementById("auth").innerText = "DEMO MODE";
}

function signup() {
  fetch("/auth/signup", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  }).then(r=>r.json()).then(d=>auth.innerText=JSON.stringify(d,null,2));
}

function login() {
  fetch("/auth/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  }).then(r=>r.json()).then(d=>{
    TOKEN = d.access_token;
    DEMO = false;
    auth.innerText = JSON.stringify(d,null,2);
  });
}

function logout() {
  TOKEN = null;
  DEMO = false;
  auth.innerText = "{}";
}

function check() {
  const payload = {
    marketplace: marketplace.value,
    text: text.value,
    is_proactive: proactive.checked,
    days_since_order_completion: parseInt(days.value),
    order_id: order.value || null,
    store_message: store.checked
  };

  let url = DEMO ? "/v1/check" : "/v1/checks";
  let headers = {"Content-Type":"application/json"};
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;

  fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(d => result.innerText = JSON.stringify(d, null, 2))
  .catch(e => result.innerText = e.toString());
}

function clearAll() {
  text.value = "";
  result.innerText = "{}";
}
</script>

</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def root():
    return HTML