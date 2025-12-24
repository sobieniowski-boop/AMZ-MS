from __future__ import annotations
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_db
from app.saas.auth import router as auth_router
from app.saas.checks import router as checks_router

APP_VERSION = "3.0.0"

app = FastAPI(title="AMZ Message Checker SaaS", version=APP_VERSION)

# If you will call from a different domain later, configure CORS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup() -> None:
    init_db()

app.include_router(auth_router)
app.include_router(checks_router)

@app.get("/health")
def health():
    return {"ok": True, "version": APP_VERSION}

CLIENT_HTML = """<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Amazon Comms Checker</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;max-width:1000px;margin:24px auto;padding:0 16px}
    textarea{width:100%;min-height:180px}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:12px 0}
    .card{border:1px solid #ddd;border-radius:12px;padding:14px}
    button{padding:10px 14px;border-radius:10px;border:1px solid #999;background:#fff;cursor:pointer}
    input,select{padding:8px;border-radius:10px;border:1px solid #bbb}
    code,pre{background:#f6f6f6;padding:10px;border-radius:10px;overflow:auto}
    .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid #999}
    .muted{color:#666}
  </style>
</head>
<body>
  <h2>Amazon Comms Compliance Checker</h2>
  <p class="muted">DEMO działa bez logowania (/v1/check). Po zalogowaniu zapisuje historię i liczy limity (/v1/checks).</p>

  <div class="card">
    <h3>Login / Signup</h3>
    <div class="row">
      <input id="email" type="email" placeholder="email" />
      <input id="password" type="password" placeholder="min 8 znaków" />
      <button id="signupBtn">Sign up</button>
      <button id="loginBtn">Login</button>
      <button id="logoutBtn">Logout</button>
      <span class="pill" id="modePill">DEMO</span>
    </div>
    <pre id="authOut">{}</pre>
  </div>

  <div class="card" style="margin-top:14px">
    <h3>Message</h3>
    <div class="row">
      <label>Marketplace:
        <select id="marketplace">
          <option value="DE">DE</option>
          <option value="PL">PL</option>
          <option value="FR">FR</option>
          <option value="IT">IT</option>
          <option value="ES">ES</option>
          <option value="NL">NL</option>
          <option value="BE">BE</option>
          <option value="SE">SE</option>
        </select>
      </label>

      <label><input type="checkbox" id="proactive" /> Proactive</label>

      <label>Days since completion:
        <input id="days" type="number" value="0" min="0" style="width:90px" />
      </label>

      <label>Order ID:
        <input id="orderId" type="text" placeholder="opcjonalnie" />
      </label>

      <label>Store message:
        <input type="checkbox" id="storeMessage" />
      </label>
    </div>

    <textarea id="message" placeholder="Wklej wiadomość do klienta..."></textarea>

    <div class="row">
      <button id="checkBtn">Sprawdź</button>
      <button id="clearBtn" type="button">Wyczyść</button>
    </div>
  </div>

  <h3>Wynik</h3>
  <pre id="out">{}</pre>

<script>
  function getToken(){ return localStorage.getItem("token"); }
  function setToken(t){ localStorage.setItem("token", t); }
  function clearToken(){ localStorage.removeItem("token"); }

  function setModePill(){
    const pill = document.getElementById("modePill");
    pill.textContent = getToken() ? "SAAS (zapis + limity)" : "DEMO";
  }
  setModePill();

  async function api(path, method, body, auth){
    const headers = {"Content-Type":"application/json"};
    if(auth){
      const t = getToken();
      if(t) headers["Authorization"] = "Bearer " + t;
    }
    const res = await fetch(path, {method, headers, body: body ? JSON.stringify(body) : undefined});
    let data = null;
    try{ data = await res.json(); } catch(e){ data = {"error":"Bad JSON", "status":res.status}; }
    return {res, data};
  }

  document.getElementById("signupBtn").addEventListener("click", async () => {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const {res, data} = await api("/auth/signup", "POST", {email, password}, false);
    document.getElementById("authOut").textContent = JSON.stringify({status: res.status, data}, null, 2);
  });

  document.getElementById("loginBtn").addEventListener("click", async () => {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const {res, data} = await api("/auth/login", "POST", {email, password}, false);
    if(res.status === 200 && data.access_token){
      setToken(data.access_token);
    }
    setModePill();
    document.getElementById("authOut").textContent = JSON.stringify({status: res.status, data}, null, 2);
  });

  document.getElementById("logoutBtn").addEventListener("click", () => {
    clearToken(); setModePill();
    document.getElementById("authOut").textContent = "{}";
  });

  document.getElementById("clearBtn").addEventListener("click", () => {
    document.getElementById("message").value = "";
    document.getElementById("out").textContent = "{}";
  });

  document.getElementById("checkBtn").addEventListener("click", async () => {
    const marketplace = document.getElementById("marketplace").value;
    const proactive = document.getElementById("proactive").checked;
    const days = parseInt(document.getElementById("days").value || "0", 10);
    const orderId = document.getElementById("orderId").value || null;
    const storeMessage = document.getElementById("storeMessage").checked;
    const message = document.getElementById("message").value || "";

    const token = getToken();
    if(!token){
      const {res, data} = await api("/v1/check", "POST", {
        marketplace,
        text: message,
        is_proactive: proactive,
        days_since_order_completion: days,
        order_id: orderId
      }, false);
      document.getElementById("out").textContent = JSON.stringify({status: res.status, endpoint:"/v1/check", data}, null, 2);
      return;
    }

    const {res, data} = await api("/v1/checks", "POST", {
      marketplace,
      message,
      proactive,
      days_since_completion: days,
      order_id: orderId,
      message_type: "generic",
      store_message: storeMessage
    }, true);

    document.getElementById("out").textContent = JSON.stringify({status: res.status, endpoint:"/v1/checks", data}, null, 2);
  });
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return CLIENT_HTML
