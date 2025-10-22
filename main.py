# main.py — FastAPI POS Wallet mit Login (Sessions) und Admin-Benutzerverwaltung
from fastapi import FastAPI, Request, Depends, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, conint
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Index
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
from typing import Optional, Literal, Dict, List
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
import secrets
import pathlib
import os
import base64
import json
import time
import requests
from dotenv import load_dotenv
import sys

load_dotenv()

# -------------------------
# App
# -------------------------
app = FastAPI(title="Simple POS Wallet")

# Session Secret
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_to_a_long_random_secret")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax")

# Passwort-Hashing
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# -------------------------
# DB Setup (SQLite) - optional legacy (nicht genutzt für TX)
# -------------------------
DB_PATH = "db.sqlite3"
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class Wallet(Base):
    __tablename__ = "wallets"
    token_id = Column(String(128), primary_key=True)
    balance_cents = Column(Integer, nullable=False, default=0)
    status = Column(String(16), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_tx_id = Column(String(64), nullable=True)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String(64), primary_key=True)
    token_id = Column(String(128), nullable=False, index=True)
    type = Column(String(16), nullable=False)  # topup | debit | refund | wallet_create
    amount_cents = Column(Integer, nullable=False)
    actor = Column(String(64), nullable=False)
    reference = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Index("idx_tx_token_created", Transaction.token_id, Transaction.created_at)
Base.metadata.create_all(engine)

# -------------------------
# Schemas
# -------------------------
class CreateWalletResp(BaseModel):
    token_id: str
    balance_cents: int

class TxRequest(BaseModel):
    token: str = Field(..., description="Wallet token")
    amount_cents: conint(gt=0)
    actor: str = "pos-1"
    reference: Optional[str] = None
    idempotency_key: Optional[str] = None

class WalletResp(BaseModel):
    token_id: str
    balance_cents: int
    status: str
    updated_at: datetime

class TxResp(BaseModel):
    ok: bool
    new_balance_cents: Optional[int] = None
    error: Optional[str] = None

# -------------------------
# Helpers (Zeit, IDs)
# -------------------------
def now_utc():
    return datetime.now(timezone.utc)

def now_utc_iso():
    # Konsistentes Z-Suffix (RFC3339)
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def generate_token():
    return "TOKEN_" + secrets.token_urlsafe(24)

def generate_tx_id(prefix: str = "tx"):
    ms = int(datetime.now().timestamp() * 1000)
    rnd = secrets.token_hex(4)
    return f"{prefix}_{ms}_{rnd}"

# -------------------------
# Benutzer-Store (users.json)
# -------------------------
USERS_PATH = os.getenv("USERS_PATH", "users.json")

def load_users() -> Dict[str, dict]:
    if not os.path.exists(USERS_PATH):
        default = {
            # Standard-Admin für ersten Login (bitte Passwort danach ändern!)
            "Julien09": {"password_hash": pwd_ctx.hash("admin123"), "role": "admin", "active": True},
            # Beispiel-Kassierer
            "kasse1": {"password_hash": pwd_ctx.hash("pass123"), "role": "cashier", "active": True},
        }
        with open(USERS_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users: Dict[str, dict]):
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def verify_password(plain: str, password_hash: str) -> bool:
    try:
        return pwd_ctx.verify(plain, password_hash)
    except Exception:
        return False

def current_user_record(request: Request):
    """Liefert (username, record) oder (None, None)."""
    u = request.session.get("user")
    if not u:
        return None, None
    users = load_users()
    rec = users.get(u)
    if not rec:
        return None, None
    return u, rec

def current_user(request: Request) -> Optional[dict]:
    u, rec = current_user_record(request)
    if not u or not rec:
        return None
    # active-Flag mitgeben
    return {"username": u, "role": rec.get("role", "cashier"), "active": rec.get("active", True)}

def guard_role(required: Optional[Literal["admin", "cashier"]] = None):
    def dep(request: Request):
        cu = current_user(request)
        if not cu:
            raise HTTPException(status_code=401, detail="unauthorized")
        if not cu.get("active", True):
            # deaktiviert -> Redirect auf /deactivated
            return HTMLResponse('<script>location.href="/deactivated";</script>', status_code=307)
        if required and cu["role"] != required:
            raise HTTPException(status_code=403, detail="forbidden")
        return cu
    return dep

def guard_cashier_or_admin(request: Request):
    cu = current_user(request)
    if not cu:
        raise HTTPException(status_code=401, detail="unauthorized")
    if not cu.get("active", True):
        return HTMLResponse('<script>location.href="/deactivated";</script>', status_code=307)
    if cu["role"] not in ("cashier", "admin"):
        raise HTTPException(status_code=403, detail="forbidden")
    return cu

# -------------------------
# GitHub Storage (db.txt)
# -------------------------
GH_OWNER = os.getenv("GH_OWNER", "jojosstudio")
GH_REPO = os.getenv("GH_REPO", "bong")
GH_PATH = os.getenv("GH_PATH", "db.txt")
GH_BRANCH = os.getenv("GH_BRANCH", "main")
GH_TOKEN = os.getenv("GITHUB_TOKEN")  # setze in deiner Umgebung
GH_API_BASE = "https://api.github.com"

def gh_headers():
    if not GH_TOKEN:
        raise RuntimeError("GITHUB_TOKEN nicht gesetzt")
    return {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pos-wallet"
    }

def gh_get_file():
    url = f"{GH_API_BASE}/repos/{GH_OWNER}/{GH_REPO}/contents/{GH_PATH}"
    params = {"ref": GH_BRANCH}
    r = requests.get(url, headers=gh_headers(), params=params, timeout=20)
    if r.status_code == 200:
        data = r.json()
        content_b64 = data["content"]
        sha = data["sha"]
        content = base64.b64decode(content_b64).decode("utf-8")
        return content, sha
    elif r.status_code == 404:
        return "", None
    else:
        raise RuntimeError(f"GitHub GET failed: {r.status_code} {r.text}")

def gh_put_file(new_content_str: str, sha: Optional[str], message: str):
    url = f"{GH_API_BASE}/repos/{GH_OWNER}/{GH_REPO}/contents/{GH_PATH}"
    payload = {
        "message": message,
        "content": base64.b64encode(new_content_str.encode("utf-8")).decode("ascii"),
        "branch": GH_BRANCH,
        "committer": {"name": "POS Wallet", "email": "pos@example.com"}
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(url, headers=gh_headers(), json=payload, timeout=20)
    if r.status_code in (200, 201):
        return r.json()
    else:
        raise RuntimeError(f"GitHub PUT failed: {r.status_code} {r.text}")

def load_db_from_github():
    text, _sha = gh_get_file()
    if text.strip() == "":
        return {"wallets": {}, "transactions": []}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"wallets": {}, "transactions": [{"raw_migrated": text, "ts": now_utc_iso()}]}

def apply_transaction_via_github(token: str, amount_cents: int, actor: str,
                                 tx_type: Literal["topup","debit"], reference: Optional[str],
                                 idempotency_key: Optional[str]):
    if not GH_TOKEN:
        return False, None, "missing_github_token"

    retries = 5
    for attempt in range(retries):
        text, sha = gh_get_file()
        if text.strip() == "":
            db = {"wallets": {}, "transactions": []}
        else:
            try:
                db = json.loads(text)
            except json.JSONDecodeError:
                db = {"wallets": {}, "transactions": [{"raw_migrated": text, "ts": now_utc_iso()}]}

        tx_id = idempotency_key or generate_tx_id(tx_type)
        if any(item.get("id") == tx_id for item in db["transactions"]):
            bal = int(db["wallets"].get(token, 0))
            return True, bal, None

        bal = int(db["wallets"].get(token, 0))
        if tx_type == "topup":
            bal += int(amount_cents)
        elif tx_type == "debit":
            if bal < int(amount_cents):
                return False, bal, "insufficient_funds"
            bal -= int(amount_cents)
        else:
            return False, bal, "unsupported_tx_type"

        db["wallets"][token] = bal
        db["transactions"].append({
            "id": tx_id,
            "token": token,
            "type": tx_type,
            "amount_cents": int(amount_cents),
            "actor": actor,
            "reference": reference,
            "ts": now_utc_iso()
        })

        new_text = json.dumps(db, ensure_ascii=False, separators=(",", ":"))
        try:
            gh_put_file(new_text, sha, message=f"{tx_type} {amount_cents} for {token}")
            return True, bal, None
        except RuntimeError as e:
            if "409" in str(e) or "sha" in str(e).lower():
                time.sleep(0.4 + attempt * 0.3)
                continue
            return False, None, str(e)

    return False, None, "github_write_conflict"

def get_wallet_from_github(token: str):
    try:
        text, _sha = gh_get_file()
        if text.strip() == "":
            return None
        db = json.loads(text)
        bal = int(db.get("wallets", {}).get(token, 0))
        return {
            "token_id": token,
            "balance_cents": bal,
            "status": "active",
            "updated_at": now_utc()
        }
    except Exception:
        return None

def list_transactions_from_github(token: Optional[str], limit: int = 100):
    text, _sha = gh_get_file()
    if text.strip() == "":
        return []
    try:
        db = json.loads(text)
    except json.JSONDecodeError:
        return [{"raw": text, "ts": now_utc_iso()}]
    items = db.get("transactions", [])
    if token:
        items = [t for t in items if t.get("token") == token]
    def sort_key(t):
        return t.get("ts", "")
    items = sorted(items, key=sort_key, reverse=True)
    return items[:limit]

# -------------------------
# Templates
# -------------------------
def resource_path(rel_path: str) -> str:
    base_path = getattr(sys, "_MEIPASS", pathlib.Path(__file__).parent)
    return str(pathlib.Path(base_path) / rel_path)

TEMPLATES_DIR = resource_path("templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# -------------------------
# Auth: Login/Logout/Me
# -------------------------
@app.get("/api/admin/wallets")
def admin_list_wallets(cu: dict = Depends(guard_role("admin")), q: Optional[str] = Query(None), limit: int = Query(1000, ge=1, le=100000)):
    """
    Liefert eine Liste aller Wallets: [{"token_id": "...", "balance_cents": 1234}]
    Optional q=... filtert nach Token substring
    limit begrenzt die Anzahl (Default 1000)
    """
    text, _sha = gh_get_file()
    if text.strip() == "":
        return []
    try:
        db = json.loads(text)
    except json.JSONDecodeError:
        return []
    wallets = db.get("wallets", {})
    items = [{"token_id": t, "balance_cents": int(b or 0)} for t, b in wallets.items()]
    if q:
        ql = q.lower()
        items = [w for w in items if ql in w["token_id"].lower()]
    items.sort(key=lambda x: x["token_id"])
    return items[:limit]

@app.get("/wallets", response_class=HTMLResponse)
def wallets_page(request: Request, cu: dict = Depends(guard_role("admin"))):
    # Nur Admin darf Seite sehen; Inhalte lädt das Frontend via /api/admin/wallets
    return templates.TemplateResponse("wallets.html", {"request": request, "me": cu})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    users = load_users()
    rec = users.get(username)
    if not rec or not verify_password(password, rec.get("password_hash","")):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Ungültige Zugangsdaten"}, status_code=401)
    if not rec.get("active", True):
        try:
            request.session.clear()
        except:
            pass
        return HTMLResponse('<script>location.href="/deactivated";</script>')
    request.session["user"] = username
    return HTMLResponse('<script>location.href="/";</script>')

@app.post("/api/login-json")
async def login_json(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    username = (data or {}).get("username","")
    password = (data or {}).get("password","")
    users = load_users()
    rec = users.get(username)
    if not rec or not verify_password(password, rec.get("password_hash","")):
        return JSONResponse(status_code=401, content={"ok": False, "error":"invalid_credentials"})
    if not rec.get("active", True):
        try:
            request.session.clear()
        except:
            pass
        return JSONResponse(status_code=403, content={"ok": False, "error": "deactivated"})
    request.session["user"] = username
    return {"ok": True, "user": username, "role": rec.get("role","cashier")}

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return HTMLResponse('<script>location.href="/login";</script>')

@app.get("/me")
def me(request: Request):
    cu = current_user(request)
    if not cu:
        return {"ok": False}
    return {"ok": True, "user": cu["username"], "role": cu["role"]}

# -------------------------
# Cashbook HTML-Seite (Admin-only)
# -------------------------
@app.get("/cashbook", response_class=HTMLResponse)
def cashbook_page(request: Request, cu: dict = Depends(guard_role("admin"))):
    # Nur Admin darf die Seite sehen; Inhalte lädt das Frontend via /api/admin/cashbook
    return templates.TemplateResponse("cashbook.html", {"request": request, "me": cu})

# -------------------------
# Cashbook API (GitHub-backed, Admin-only)
# -------------------------
@app.get("/api/admin/cashbook")
def admin_list_cashbook(
    cu: dict = Depends(guard_role("admin")),
    q: Optional[str] = Query(None, description="Filtert nach Notiz-Substring"),
    type_: Optional[str] = Query(None, alias="type", description="income oder expense"),
    by: Optional[str] = Query(None, description="Username-Filter"),
    limit: int = Query(1000, ge=1, le=100000),
    sort: str = Query("ts_desc", description="ts_asc|ts_desc|amount_desc|amount_asc")
):
    """
    Liefert eine Liste der Kassenbuch-Einträge:
    [{"id":"...","ts":"2025-10-22T09:30:00Z","type":"income|expense","amount_cents":1234,"note":"...","by":"username"}]
    """
    try:
        text, _sha = gh_get_file()
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": f"github_read_failed: {str(e)}"})

    if text.strip() == "":
        return []

    try:
        db = json.loads(text)
    except json.JSONDecodeError as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": f"json_invalid_db: {str(e)}"})

    entries: List[dict] = db.get("cashbook", []) or []
    if not isinstance(entries, list):
        return JSONResponse(status_code=500, content={"ok": False, "error": "cashbook_not_a_list"})

    # Normalize / defaults
    norm = []
    for e in entries:
        try:
            norm.append({
                "id": str(e.get("id") or ""),
                "ts": str(e.get("ts") or ""),
                "type": str(e.get("type") or "income"),
                "amount_cents": int(e.get("amount_cents") or 0),
                "note": str(e.get("note") or ""),
                "by": str(e.get("by") or ""),
            })
        except Exception:
            continue

    # Filter
    if q:
        ql = q.lower()
        norm = [e for e in norm if ql in (e["note"] or "").lower()]
    if type_ in ("income", "expense"):
        norm = [e for e in norm if e["type"] == type_]
    if by:
        norm = [e for e in norm if e["by"] == by]

    # Sortierung
    if sort == "ts_asc":
        norm.sort(key=lambda x: x["ts"])
    elif sort == "amount_desc":
        norm.sort(key=lambda x: x["amount_cents"], reverse=True)
    elif sort == "amount_asc":
        norm.sort(key=lambda x: x["amount_cents"])
    else:
        norm.sort(key=lambda x: x["ts"], reverse=True)

    return norm[:limit]

@app.post("/api/admin/cashbook")
async def admin_add_cashbook_entry(
    request: Request,
    cu: dict = Depends(guard_role("admin"))
):
    """
    JSON-Body:
      { "type": "income"|"expense", "amount_cents": 1234, "note": "Text" }
    Antwort: {"ok": True, "id": "..."}
    """
    try:
        data = await request.json()
    except Exception:
        data = {}

    type_ = (data or {}).get("type", "income")
    try:
        amount_cents = int((data or {}).get("amount_cents", 0))
    except Exception:
        amount_cents = 0
    note = (data or {}).get("note", "")[:2000]
    by = cu.get("username", "")

    if type_ not in ("income", "expense"):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_type"})
    if amount_cents <= 0:
        return JSONResponse(status_code=400, content={"ok": False, "error": "amount_must_be_positive"})

    text, sha = gh_get_file()
    db = {}
    if text.strip() != "":
        try:
            db = json.loads(text)
        except json.JSONDecodeError:
            db = {}

    entries: List[dict] = db.get("cashbook", []) or []

    import uuid
    eid = uuid.uuid4().hex
    ts = now_utc_iso()

    entry = {
        "id": eid,
        "ts": ts,
        "type": type_,
        "amount_cents": amount_cents,
        "note": note,
        "by": by,
    }
    entries.append(entry)
    db["cashbook"] = entries

    try:
        gh_put_file(json.dumps(db, ensure_ascii=False, indent=2), sha, message=f"cashbook {type_} {amount_cents}")
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

    return {"ok": True, "id": eid}

@app.delete("/api/admin/cashbook/{eid}")
def admin_delete_cashbook_entry(
    eid: str,
    cu: dict = Depends(guard_role("admin"))
):
    """
    Entfernt einen Kassenbuch-Eintrag per ID.
    Antwort: {"ok": True} oder {"ok": False, "error": "..."}
    """
    text, sha = gh_get_file()
    db = {}
    if text.strip() != "":
        try:
            db = json.loads(text)
        except json.JSONDecodeError:
            db = {}

    entries: List[dict] = db.get("cashbook", []) or []
    new_entries = [e for e in entries if str(e.get("id")) != eid]

    if len(new_entries) == len(entries):
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    db["cashbook"] = new_entries
    try:
        gh_put_file(json.dumps(db, ensure_ascii=False, indent=2), sha, message=f"cashbook delete {eid}")
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

    return {"ok": True}

# -------------------------
# Weitere API endpoints (GitHub-backed) mit Auth-Guards
# -------------------------
@app.get("/automation", response_class=HTMLResponse)
def automation_page(request: Request, cu: dict = Depends(guard_role("admin"))):
    # Nur Admin darf die Seite sehen
    return templates.TemplateResponse("automation.html", {"request": request, "me": cu})

@app.post("/api/wallets", response_model=CreateWalletResp)
def create_wallet(cu: dict = Depends(guard_role("admin"))):
    token = generate_token()
    retries = 3
    for attempt in range(retries):
        text, sha = gh_get_file()
        if text.strip() == "":
            db = {"wallets": {}, "transactions": []}
        else:
            try:
                db = json.loads(text)
            except json.JSONDecodeError:
                db = {"wallets": {}, "transactions": [{"raw_migrated": text, "ts": now_utc_iso()}]}

        if token not in db["wallets"]:
            db["wallets"][token] = 0
            db["transactions"].append({
                "id": generate_tx_id("wallet_create"),
                "token": token,
                "type": "wallet_create",
                "amount_cents": 0,
                "actor": cu["username"],
                "reference": None,
                "ts": now_utc_iso()
            })

        new_text = json.dumps(db, ensure_ascii=False, separators=(",", ":"))
        try:
            gh_put_file(new_text, sha, message=f"create wallet {token}")
            return {"token_id": token, "balance_cents": 0}
        except RuntimeError as e:
            if "409" in str(e) or "sha" in str(e).lower():
                time.sleep(0.3 + attempt * 0.2)
                continue
            return JSONResponse(status_code=500, content={"detail": str(e)})

    return JSONResponse(status_code=409, content={"detail": "github_write_conflict"})

@app.get("/api/wallets/{token}", response_model=WalletResp)
def get_wallet(token: str, cu: dict = Depends(guard_cashier_or_admin)):
    w = get_wallet_from_github(token)
    if not w:
        return JSONResponse(status_code=404, content={"detail": "wallet_not_found"})
    return w

@app.post("/api/topup", response_model=TxResp)
def topup(req: TxRequest, cu: dict = Depends(guard_cashier_or_admin)):
    ok, bal, err = apply_transaction_via_github(req.token, req.amount_cents, cu["username"], "topup", req.reference, req.idempotency_key)
    if ok:
        return {"ok": True, "new_balance_cents": bal}
    status = 400
    return JSONResponse(status_code=status, content={"ok": False, "error": err, "new_balance_cents": bal})

@app.post("/api/debit", response_model=TxResp)
def debit(req: TxRequest, cu: dict = Depends(guard_cashier_or_admin)):
    ok, bal, err = apply_transaction_via_github(req.token, req.amount_cents, cu["username"], "debit", req.reference, req.idempotency_key)
    if ok:
        return {"ok": True, "new_balance_cents": bal}
    status = 409 if err == "insufficient_funds" else 400
    return JSONResponse(status_code=status, content={"ok": False, "error": err, "new_balance_cents": bal})

@app.get("/api/transactions")
def list_transactions(token: Optional[str] = None, limit: int = 100, cu: dict = Depends(guard_cashier_or_admin)):
    try:
        items = list_transactions_from_github(token, limit)
        return items
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})

# -------------------------
# Admin-Page & Admin-Aktionen
# -------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, cu: dict = Depends(guard_role("admin"))):
    users = load_users()
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "me": cu})

@app.post("/admin/create")
def admin_create(request: Request, cu: dict = Depends(guard_role("admin")),
                 username: str = Form(...), password: str = Form(...), role: str = Form("cashier")):
    users = load_users()
    if username in users:
        return HTMLResponse('<script>alert("User existiert");history.back();</script>', status_code=400)
    users[username] = {
        "password_hash": pwd_ctx.hash(password),
        "role": role if role in ("cashier","admin") else "cashier",
        "active": True
    }
    save_users(users)
    return HTMLResponse('<script>location.href="/admin";</script>')

@app.post("/admin/setrole")
def admin_setrole(request: Request, cu: dict = Depends(guard_role("admin")),
                  username: str = Form(...), role: str = Form(...)):
    users = load_users()
    if username not in users:
        return HTMLResponse('<script>alert("User nicht gefunden");history.back();</script>', status_code=404)
    users[username]["role"] = role if role in ("cashier","admin") else "cashier"
    save_users(users)
    return HTMLResponse('<script>location.href="/admin";</script>')

@app.post("/admin/setactive")
def admin_setactive(request: Request, cu: dict = Depends(guard_role("admin")),
                    username: str = Form(...), active: str = Form(...)):
    users = load_users()
    if username not in users:
        return HTMLResponse('<script>alert("User nicht gefunden");history.back();</script>', status_code=404)
    users[username]["active"] = (active.lower() == "true")
    save_users(users)
    return HTMLResponse('<script>location.href="/admin";</script>')

@app.post("/admin/resetpass")
def admin_resetpass(request: Request, cu: dict = Depends(guard_role("admin")),
                    username: str = Form(...), new_password: str = Form(...)):
    users = load_users()
    if username not in users:
        return HTMLResponse('<script>alert("User nicht gefunden");history.back();</script>', status_code=404)
    users[username]["password_hash"] = pwd_ctx.hash(new_password)
    save_users(users)
    return HTMLResponse('<script>location.href="/admin";</script>')

@app.post("/admin/delete")
def admin_delete(request: Request, cu: dict = Depends(guard_role("admin")),
                 username: str = Form(...)):
    users = load_users()
    if username not in users:
        return HTMLResponse('<script>alert("User nicht gefunden");history.back();</script>', status_code=404)
    if username == cu["username"]:
        return HTMLResponse('<script>alert("Eigenen Admin nicht löschen");history.back();</script>', status_code=400)
    del users[username]
    save_users(users)
    return HTMLResponse('<script>location.href="/admin";</script>')

# -------------------------
# UI (Index) mit Auth-Redirect
# -------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    cu = current_user(request)
    if not cu:
        return HTMLResponse('<script>location.href="/login";</script>')
    if not cu.get("active", True):
        try:
            request.session.clear()
        except:
            pass
        return HTMLResponse('<script>location.href="/deactivated";</script>')
    return templates.TemplateResponse("index.html", {"request": request, "user": cu})

@app.get("/deactivated", response_class=HTMLResponse)
def deactivated_page(request: Request):
    return templates.TemplateResponse("deactivated.html", {"request": request})

# -------------------------
# Direktstart
# -------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
