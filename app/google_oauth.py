import os
import httpx
from fastapi import HTTPException

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URL = os.getenv("GOOGLE_REDIRECT_URL", "")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


def build_google_auth_url(state: str) -> str:
    if not (GOOGLE_CLIENT_ID and GOOGLE_REDIRECT_URL):
        raise RuntimeError("GOOGLE_CLIENT_ID/GOOGLE_REDIRECT_URL not set")

    # scope minimalny: email + profile + openid
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URL,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
    }

    # ręcznie składamy query (bez dodatkowych deps)
    from urllib.parse import urlencode
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_id_token(code: str) -> str:
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URL):
        raise RuntimeError("Google OAuth env not set")

    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URL,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(GOOGLE_TOKEN_URL, data=data)

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Google token exchange failed")

    token_json = r.json()
    id_token = token_json.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="No id_token from Google")
    return id_token


async def get_profile_from_id_token(id_token: str) -> dict:
    # tokeninfo weryfikuje token (praktyczne MVP). Docelowo można zrobić pełną weryfikację podpisu.
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(GOOGLE_TOKENINFO_URL, params={"id_token": id_token})

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Google token verification failed")

    info = r.json()
    # podstawowe pola:
    # sub, email, email_verified, name, picture
    return info
