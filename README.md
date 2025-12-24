# AMZ Message Checker SaaS (FastAPI)

## Local run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="dev-secret"
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000/ (UI)
- http://127.0.0.1:8000/docs (API)

## Render
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Env vars:
  - `JWT_SECRET` (required)
  - `DATABASE_URL` (optional; if missing uses SQLite file at `./data/app.db`)
  - `FREE_DAILY_LIMIT` (optional; default 25)
  - `PRO_DAILY_LIMIT` (optional; default 500)
