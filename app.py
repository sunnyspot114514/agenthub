from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator

try:
    from fastmcp.exceptions import ToolError
except Exception:  # pragma: no cover
    class ToolError(Exception):
        pass

ROOT = Path(os.environ.get("AGENTHUB_ROOT", Path(__file__).resolve().parent))
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(mode=0o700, exist_ok=True)
DB_PATH = Path(os.environ.get("AGENTHUB_DB", str(DATA_DIR / "hub.db")))

from hubv1 import timeutil as hubtime
from hubv1.api import router as v1_router
from hubv1.api import shared_router as v1_shared_router
from hubv1.pages import access_page, agent_workspaces_page, chat_page, library_page, logs_page, overview_page, profile_page, publish_page, workspace_page
from hubv1.store import connect as v1_connect
from hubv1.store import init_v1, touch_seen
from hubv1.align import ensure_due_for_identities
from hubv1.version import APP_VERSION

APP_NAME = "Agenthub"
PUBLIC_HOST = os.getenv("AGENTHUB_PUBLIC_HOST", "agenthub.sunny99.win")
PUBLIC_ORIGIN = f"https://{PUBLIC_HOST}"
API_TOKEN = os.getenv("AGENTHUB_API_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
SESSION_SECRET = os.getenv("AGENTHUB_SESSION_SECRET", "")

HEARTBEAT_INTERVAL = int(os.getenv("AGENTHUB_HEARTBEAT_INTERVAL", "60"))
OFFLINE_AFTER = int(os.getenv("AGENTHUB_OFFLINE_AFTER", "180"))
SESSION_HOURS = int(os.getenv("AGENTHUB_SESSION_HOURS", "12"))
PUBLIC_TTL = 60
MAX_BODY = 210 * 1024 * 1024
MAX_PAGE = 50
MAX_QUEUE = 100
LOG_KEEP_DAYS = 14
LOG_MAX_ROWS = 5000
PBKDF2_ROUNDS = 120_000
TASK_TYPES = {"note"}

ALLOWED_ORIGINS = {PUBLIC_ORIGIN, "http://127.0.0.1:8000", "http://localhost:8000"}
STARTED = time.time()

_public_cache: dict[str, Any] = {"at": 0.0, "data": None, "error": None}
_rate: dict[str, deque] = defaultdict(deque)
_token_cache: dict[str, tuple[str, float]] = {}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def ensure_session_secret() -> str:
    global SESSION_SECRET
    if SESSION_SECRET:
        return SESSION_SECRET
    env_path = ROOT / ".env"
    secret = secrets.token_urlsafe(32)
    with env_path.open("a", encoding="utf-8") as fh:
        fh.write(f"\nAGENTHUB_SESSION_SECRET={secret}\n")
    os.chmod(env_path, 0o600)
    os.environ["AGENTHUB_SESSION_SECRET"] = secret
    SESSION_SECRET = secret
    return secret


@contextmanager
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                public_alias TEXT NOT NULL DEFAULT '',
                token_salt TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                roles TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_id TEXT NOT NULL,
                received_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                assignee_id TEXT,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                title TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_completions (
                task_id TEXT PRIMARY KEY,
                completed_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                channel TEXT NOT NULL,
                body TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hb_id_time ON heartbeats(identity_id, received_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(created_at)")
        migrate_legacy(conn)
        init_v1(conn)


def migrate_legacy(conn: sqlite3.Connection) -> None:
    task_cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()}
    if task_cols and "owner_id" not in task_cols:
        conn.execute("DROP TABLE tasks")
        conn.execute(
            """
            CREATE TABLE tasks (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                assignee_id TEXT,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                title TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
    msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)").fetchall()}
    if msg_cols and "owner_id" not in msg_cols:
        conn.execute("DROP TABLE messages")
        conn.execute(
            """
            CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                channel TEXT NOT NULL,
                body TEXT NOT NULL
            )
            """
        )


def hash_token(token: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def new_token_parts(token: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16).hex()
    return salt, hash_token(token, salt)


def bootstrap_admin() -> None:
    if not API_TOKEN:
        raise RuntimeError("AGENTHUB_API_TOKEN missing; refusing to start unprotected")
    salt, digest = new_token_parts(API_TOKEN)
    now = utcnow_iso()
    with db() as conn:
        row = conn.execute("SELECT id, token_salt FROM identities WHERE id='admin'").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO identities(id, kind, public_alias, token_salt, token_hash, roles, expires_at, revoked_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "admin",
                    "admin",
                    "",
                    salt,
                    digest,
                    json.dumps(["view", "dispatch", "manage", "report"]),
                    None,
                    None,
                    now,
                ),
            )
        else:
            digest = hash_token(API_TOKEN, row["token_salt"])
            conn.execute("UPDATE identities SET token_hash=?, revoked_at=NULL WHERE id='admin'", (digest,))


def prune_old() -> None:
    cutoff = (utcnow() - timedelta(days=LOG_KEEP_DAYS)).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
        conn.execute("DELETE FROM heartbeats WHERE received_at < ?", (cutoff,))
        n = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        if n > LOG_MAX_ROWS:
            conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY created_at ASC LIMIT ?)",
                (n - LOG_MAX_ROWS,),
            )


def record_event(kind: str, source: str, payload: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO events(id, created_at, kind, source, payload) VALUES (?,?,?,?,?)",
            (str(secrets.token_hex(16)), utcnow_iso(), kind, source, json.dumps(payload, ensure_ascii=False)),
        )


class Principal:
    def __init__(self, row: sqlite3.Row):
        self.id = row["id"]
        self.kind = row["kind"]
        self.public_alias = row["public_alias"] or ""
        self.roles = set(json.loads(row["roles"]))
        self.expires_at = row["expires_at"]
        self.revoked_at = row["revoked_at"]
        self.oauth_grant_id = None
        self.oauth_scopes = None
        self.oauth_client_id = None
        self.upload_ticket = None

    def has(self, role: str) -> bool:
        return role in self.roles or "manage" in self.roles


def _identity_usable(row: sqlite3.Row) -> bool:
    if row["revoked_at"]:
        return False
    if row["expires_at"] and row["expires_at"] < utcnow_iso():
        return False
    return True


def principal_from_token(token: str) -> Optional[Principal]:
    if not token or len(token) > 200:
        return None
    if token.startswith("oht_"):
        from hubv1.xfer import lookup_ticket

        rec = lookup_ticket(token)
        if not rec:
            return None
        with db() as conn:
            row = conn.execute("SELECT * FROM identities WHERE id=?", (rec["identity_id"],)).fetchone()
        if not row or not _identity_usable(row):
            return None
        p = Principal(row)
        p.upload_ticket = rec
        p.oauth_grant_id = "upload-ticket"
        p.oauth_scopes = {"hub:read", "workspace:write:own"}
        return p
    if token.startswith("oha_"):
        from hubv1.oauth_store import lookup_access

        rec = lookup_access(token)
        if not rec:
            return None
        with db() as conn:
            row = conn.execute("SELECT * FROM identities WHERE id=?", (rec["identity_id"],)).fetchone()
        if not row or not _identity_usable(row):
            return None
        p = Principal(row)
        p.oauth_grant_id = rec.get("grant_id")
        p.oauth_scopes = set(rec.get("scopes") or [])
        p.oauth_client_id = rec.get("client_id")
        return p
    cache_key = hmac.new(ensure_session_secret().encode(), token.encode(), hashlib.sha256).hexdigest()
    cached = _token_cache.get(cache_key)
    now = time.time()
    if cached and cached[1] > now:
        with db() as conn:
            row = conn.execute("SELECT * FROM identities WHERE id=?", (cached[0],)).fetchone()
        if row and _identity_usable(row):
            return Principal(row)
    with db() as conn:
        rows = conn.execute("SELECT * FROM identities").fetchall()
    for row in rows:
        if not _identity_usable(row):
            continue
        digest = hash_token(token, row["token_salt"])
        if hmac.compare_digest(digest, row["token_hash"]):
            _token_cache[cache_key] = (row["id"], now + 30)
            return Principal(row)
    return None


def principal_from_session(session_id: str) -> Optional[Principal]:
    if not session_id:
        return None
    with db() as conn:
        sess = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not sess or sess["revoked_at"] or sess["expires_at"] < utcnow_iso():
            return None
        row = conn.execute("SELECT * FROM identities WHERE id=?", (sess["identity_id"],)).fetchone()
    if not row or not _identity_usable(row):
        return None
    return Principal(row)


def parse_cookie(header: str, name: str) -> str:
    if not header:
        return ""
    for part in header.split(";"):
        if "=" not in part:
            continue
        k, v = part.strip().split("=", 1)
        if k == name:
            return v
    return ""


def principal_from_http(
    authorization: Optional[str],
    cookie: Optional[str],
) -> Optional[Principal]:
    if authorization and authorization.lower().startswith("bearer "):
        return principal_from_token(authorization.split(" ", 1)[1].strip())
    sid = parse_cookie(cookie or "", "agenthub_session")
    if sid:
        return principal_from_session(sid)
    return None


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def rate_ok(ip: str, limit: int) -> bool:
    now = time.time()
    q = _rate[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def public_headers(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "public, max-age=60"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def private_headers(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store, no-cache, private, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["CDN-Cache-Control"] = "no-store"
    resp.headers["Cloudflare-CDN-Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return resp


def origin_ok(request: Request) -> bool:
    origin = (request.headers.get("origin") or "").strip()
    host = (request.headers.get("host") or "").split(":")[0].lower()
    referer = request.headers.get("referer") or ""

    def host_allowed(hostname: str) -> bool:
        name = (hostname or "").lower()
        return name in {PUBLIC_HOST.lower(), host, "127.0.0.1", "localhost"}

    if origin and origin.lower() != "null":
        if origin in ALLOWED_ORIGINS:
            return True
        parsed = urlparse(origin)
        if parsed.scheme in {"https", "http"} and host_allowed(parsed.hostname or ""):
            return True
        return False
    return any(referer.startswith(o + "/") or referer == o for o in ALLOWED_ORIGINS) or host_allowed(host)


def compute_public_summary() -> dict[str, Any]:
    now = hubtime.now()
    offline_iso = (now.astimezone(timezone.utc) - timedelta(seconds=OFFLINE_AFTER)).isoformat()
    today = hubtime.shanghai_date(now)
    with db() as conn:
        agent_rows = conn.execute("SELECT COUNT(*) AS n FROM identities WHERE kind='agent' AND revoked_at IS NULL").fetchone()["n"]
        recent = conn.execute(
            """
            SELECT COUNT(DISTINCT identity_id) AS n
            FROM heartbeats
            WHERE received_at >= ?
            """,
            (offline_iso,),
        ).fetchone()["n"]
        try:
            completed_today = conn.execute(
                "SELECT COUNT(*) AS n FROM worklog_entries WHERE work_date=?",
                (today,),
            ).fetchone()["n"]
        except Exception:
            completed_today = 0
        trend = []
        today_d = now.astimezone(hubtime.TZ).date()
        for i in range(6, -1, -1):
            day = (today_d - timedelta(days=i)).isoformat()
            try:
                n = conn.execute(
                    "SELECT COUNT(*) AS n FROM worklog_entries WHERE work_date=?",
                    (day,),
                ).fetchone()["n"]
            except Exception:
                n = 0
            trend.append({"date": day, "completed_tasks": int(n)})
    if agent_rows == 0:
        note = "尚未接入"
        recent = 0
    elif recent == 0:
        note = "尚未接入"
    else:
        note = "ok"
    return {
        "hub_available": True,
        "agents_recent_heartbeat": int(recent),
        "agents_note": note,
        "tasks_completed_today": int(completed_today),
        "activity_trend_7d": trend,
        "generated_at": now.isoformat(),
        "heartbeat_interval_seconds": HEARTBEAT_INTERVAL,
        "offline_after_seconds": OFFLINE_AFTER,
        "as_of": now.isoformat(),
        "timezone": "Asia/Shanghai",
        "work_date": today,
    }


def get_public_summary() -> dict[str, Any]:
    now = time.time()
    if hubtime.snapshot_state()[0] is not None:
        return compute_public_summary()
    if _public_cache["data"] is not None and now - _public_cache["at"] < PUBLIC_TTL and not _public_cache["error"]:
        return _public_cache["data"]
    try:
        data = compute_public_summary()
        _public_cache.update({"at": now, "data": data, "error": None})
        return data
    except Exception:
        _public_cache.update({"at": now, "data": None, "error": "temporarily_unavailable"})
        return {
            "hub_available": False,
            "agents_note": "暂时无法获取",
            "generated_at": utcnow_iso(),
            "unavailable_reason": "temporarily_unavailable",
        }


def scoped_tasks(p: Principal, limit: int) -> list[dict[str, Any]]:
    limit = max(1, min(limit, MAX_PAGE))
    with db() as conn:
        if p.has("manage"):
            rows = conn.execute(
                "SELECT id, created_at, updated_at, owner_id, assignee_id, type, status, title FROM tasks ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, updated_at, owner_id, assignee_id, type, status, title FROM tasks WHERE owner_id=? OR assignee_id=? ORDER BY created_at DESC LIMIT ?",
                (p.id, p.id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def scoped_events(p: Principal, limit: int) -> list[dict[str, Any]]:
    limit = max(1, min(limit, MAX_PAGE))
    with db() as conn:
        if p.has("manage"):
            rows = conn.execute(
                "SELECT id, created_at, kind, source, payload FROM events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, kind, source, payload FROM events WHERE json_extract(payload,'$.identity_id')=? OR source=? ORDER BY created_at DESC LIMIT ?",
                (p.id, p.id, limit),
            ).fetchall()
    out = []
    for r in rows:
        payload = json.loads(r["payload"])
        payload.pop("token", None)
        payload.pop("authorization", None)
        out.append(
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "kind": r["kind"],
                "source": r["source"],
                "payload": payload,
            }
        )
    return out


def scoped_messages(p: Principal, limit: int) -> list[dict[str, Any]]:
    limit = max(1, min(limit, MAX_PAGE))
    with db() as conn:
        if p.has("manage"):
            rows = conn.execute(
                "SELECT id, created_at, owner_id, sender, channel, body FROM messages ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, created_at, owner_id, sender, channel, body FROM messages WHERE owner_id=? ORDER BY created_at DESC LIMIT ?",
                (p.id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def scoped_agents(p: Principal) -> list[dict[str, Any]]:
    offline_iso = (utcnow() - timedelta(seconds=OFFLINE_AFTER)).isoformat()
    with db() as conn:
        if p.has("manage"):
            rows = conn.execute("SELECT id, kind, public_alias, revoked_at FROM identities").fetchall()
        else:
            rows = conn.execute(
                "SELECT id, kind, public_alias, revoked_at FROM identities WHERE id=?",
                (p.id,),
            ).fetchall()
        out = []
        for r in rows:
            last = conn.execute(
                "SELECT received_at FROM heartbeats WHERE identity_id=? ORDER BY received_at DESC LIMIT 1",
                (r["id"],),
            ).fetchone()
            last_at = last["received_at"] if last else None
            live = bool(last_at and last_at >= offline_iso)
            alias = r["public_alias"] or "匿名"
            item = {
                "id": r["id"] if p.has("manage") or r["id"] == p.id else "redacted",
                "kind": r["kind"],
                "display_name": alias,
                "heartbeat": "live" if live else ("expired" if last_at else "none"),
                "last_heartbeat_at": last_at,
                "revoked": bool(r["revoked_at"]),
            }
            out.append(item)
    return out


mcp = FastMCP(
    name=APP_NAME,
    instructions="Agenthub shared context hub. Authenticate with OAuth access token or owner-provisioned Bearer. Restricted write tools only. Not an LLM. No shell, SQL, or generic HTTP.",
)


def _mcp_http_request():
    try:
        from fastmcp.server.dependencies import get_http_request

        return get_http_request()
    except Exception:
        return None


def mcp_principal() -> Optional[Principal]:
    """Same Bearer/session identity as REST. FastMCP's default header helper strips Authorization."""
    request = _mcp_http_request()
    if request is not None:
        p = getattr(getattr(request, "state", None), "principal", None)
        if isinstance(p, Principal):
            return p
        p = principal_from_http(request.headers.get("authorization"), request.headers.get("cookie"))
        if p is not None:
            return p
    headers: dict[str, str] = {}
    try:
        from fastmcp.server.dependencies import get_http_headers

        headers = get_http_headers(include_all=True) or {}
    except TypeError:
        try:
            from fastmcp.server.dependencies import get_http_headers

            headers = get_http_headers(include={"authorization", "cookie", "x-api-key"}) or {}
        except Exception:
            headers = {}
    except Exception:
        headers = {}
    auth = headers.get("authorization") or headers.get("Authorization")
    cookie = headers.get("cookie") or headers.get("Cookie")
    if not auth:
        extra = headers.get("x-api-key") or headers.get("x-agenthub-token")
        if extra:
            auth = extra if str(extra).lower().startswith("bearer ") else f"Bearer {extra}"
    return principal_from_http(auth, cookie)


def mcp_require(*roles: str) -> Principal:
    p = mcp_principal()
    if p is None:
        raise ToolError("unauthorized")
    if roles and not any(p.has(r) for r in roles):
        raise ToolError("forbidden")
    from hubv1.acl import access_for

    acc = access_for(p)
    if acc.revoked and not acc.manage:
        raise ToolError("forbidden")
    return p


def hub_status_for(p: Principal) -> dict[str, Any]:
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "api_version": APP_VERSION,
        "role": "home-agent-hub",
        "identity": p.id,
        "agents": scoped_agents(p),
        "counts": {"tasks": len(scoped_tasks(p, 1)), "events": len(scoped_events(p, 1))},
    }


@mcp.tool
def get_hub_status() -> dict[str, Any]:
    """Authenticated hub status for the caller's scope. Requires view."""
    p = mcp_require("view")
    from hubv1.mcptools import mcp_surface

    out = hub_status_for(p)
    out.update(mcp_surface(p))
    return out


def _stage_file_tool(fn):
    desc = (
        "Upload the user's ZIP or file into staging and return staging_id. "
        "The host must attach the user file in `file` (file picker). "
        "Models must not invent Base64. If `file` is omitted, pass name + declared_bytes to get a one-time PUT URL."
    )
    extra = {"name": "workspace_stage_file", "description": desc}
    try:
        return mcp.tool(meta={"openai/fileParams": ["file"]}, **extra)(fn)
    except TypeError:
        return mcp.tool(**extra)(fn)


@_stage_file_tool
def workspace_stage_file(
    name: str = "",
    file: Any = None,
    content_b64: str = "",
    declared_bytes: int = 0,
    sha256: str = "",
    purpose: str = "archive",
) -> dict[str, Any]:
    """Upload a user file or ZIP. Host attaches `file`; models must not invent Base64."""
    from hubv1.mcptools import ToolFail, binary_stage

    p = mcp_require("view")
    try:
        return binary_stage(
            p,
            name=name,
            file=file,
            content_b64=content_b64,
            declared_bytes=declared_bytes,
            sha256=sha256,
            purpose=purpose,
        )
    except ToolFail as exc:
        raise ToolError(exc.as_text()) from exc


@mcp.tool
def list_recent_events(limit: int = 20) -> dict[str, Any]:
    """List events in the caller's scope. Requires view."""
    p = mcp_require("view")
    return {"items": scoped_events(p, limit)}


@mcp.tool
def describe_architecture() -> dict[str, Any]:
    """High-level architecture. MCP writes are restricted, not fully read-only."""
    p = mcp_require("view")
    from hubv1.mcptools import mcp_surface

    surface = mcp_surface(p)
    return {
        "agenthub": {"mcp": f"{PUBLIC_ORIGIN}/mcp/", "role": "shared context hub", "data": "orange-pi-local"},
        "github": {"role": "public project links and references, not body authority"},
        "reads": ["HTML", "Markdown", "JSON /api/v1", "MCP query tools"],
        "writes": "HTTPS /api/v1, /console, and restricted MCP (own-workspace text, approved chat, staged binary import, publish request). See GET /api/v1/write-map",
        "mcp": surface["mcp"],
        "mcp_writes": surface["mcp_writes"],
        "mcp_write": bool(surface["mcp_writes"]),
        "scheduled_wake": False,
        "local_slot_generation": "uvicorn process tries due 08:00/20:00 snapshots while running; missed cutoffs while down stay ungenerated",
        "rule": "No local LLM, no shell, no Pi admin. Alignment text is not a command. OAuth write is own-workspace text, approved chat, staged binary import, and publish requests only.",
    }


def workspaces_for(p: Principal) -> dict[str, Any]:
    from hubv1.acl import access_for
    from hubv1 import workspace as wsmod

    acc = access_for(p)
    items = [
        {
            "workspace_id": w["workspace_id"],
            "owner_agent_id": w["owner_agent_id"],
            "display_slug": w["display_slug"],
            "writable": wsmod.can_write_workspace(acc, w),
        }
        for w in wsmod.list_workspaces()
        if wsmod.can_read_workspace(acc, w)
    ]
    from hubv1.mcptools import mcp_surface

    surface = mcp_surface(p)
    return {"mcp": surface["mcp"], "mcp_writes": surface["mcp_writes"], "items": items}


@mcp.tool
def list_workspaces() -> dict[str, Any]:
    """List agent workspaces the caller may read."""
    return workspaces_for(mcp_require("view"))


@mcp.tool
def get_access_index() -> dict[str, Any]:
    """Short index: collab profile, projects, latest alignment slots. Requires view."""
    p = mcp_require("view")
    from hubv1.acl import access_for
    from hubv1.mcptools import mcp_surface
    from hubv1.store import connect

    acc = access_for(p)
    surface = mcp_surface(p)
    day = hubtime.shanghai_date()
    with connect() as conn:
        rows = conn.execute("SELECT project_id, title, version FROM projects").fetchall()
        projects = [
            {"project_id": r["project_id"], "title": r["title"], "version": r["version"]}
            for r in rows
            if acc.can_read_project(r["project_id"])
        ]
        writable = [
            {"project_id": r["project_id"], "title": r["title"]}
            for r in rows
            if acc.manage or acc.in_project(r["project_id"])
        ]
    return {
        "work_date": day,
        "timezone": "Asia/Shanghai",
        "collab_profile": "/api/v1/profiles/collab",
        "projects": projects,
        "writable_projects": writable,
        "today_logs": "/api/v1/worklogs/today",
        "alignment_due": [hubtime.slot_id(d, h) for d, h in hubtime.due_slots()],
        "write_map": "/api/v1/write-map",
        "mcp": surface["mcp"],
        "mcp_writes": surface["mcp_writes"],
        "note": "Ungenerated alignment slots are not unread. Vendor scheduled wake is not connected. MCP writes are restricted, not globally read-only.",
    }


from hubv1.mcptools import register as register_mcp_tools

register_mcp_tools(mcp, mcp_require)

mcp_app = mcp.http_app(path="/", transport="streamable-http")


def usable_principals() -> list[Principal]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM identities WHERE revoked_at IS NULL").fetchall()
    return [Principal(r) for r in rows if _identity_usable(r)]


async def snapshot_loop() -> None:
    while True:
        try:
            if not hubtime.clock_error():
                from hubv1.flags import flag
                from hubv1.jobs import run_due_jobs

                if flag("feature_embedded_scheduler"):
                    run_due_jobs()
                    ensure_due_for_identities(usable_principals())
        except Exception as exc:
            try:
                record_event("alignment.loop_error", "system", {"error": type(exc).__name__})
            except Exception:
                pass
        await asyncio.sleep(20)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_session_secret()
    init_db()
    bootstrap_admin()
    try:
        from hubv1.store import connect as _ws_conn
        from hubv1.workspace import ensure_all_workspaces

        with _ws_conn() as conn:
            ensure_all_workspaces(conn)
    except Exception:
        pass
    prune_old()
    record_event("hub.started", "system", {"version": APP_VERSION})
    task = asyncio.create_task(snapshot_loop())
    async with mcp_app.lifespan(_app):
        yield
    task.cancel()


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Home Agent Hub. Approved shared context, daily worklogs, and alignment snapshots. Authenticated REST and MCP. Not an LLM.",
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={"persistAuthorization": False},
    lifespan=lifespan,
)
app.mount("/mcp", mcp_app)
app.include_router(v1_router)
app.include_router(v1_shared_router)
from hubv1.oauth import router as oauth_router

app.include_router(oauth_router)

PUBLIC_PATHS = {
    "/",
    "/health",
    "/v1/public/summary",
    "/login",
    "/.well-known/agenthub.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/revoke",
    "/oauth/register",
    "/about",
    "/v1/public/profile",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/agent",
    "/agent/bootstrap.json",
    "/llms.txt",
}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request.state.request_id = secrets.token_hex(8)
    clock_prev = hubtime.snapshot_state()
    if os.getenv("AGENTHUB_ALLOW_TEST_CLOCK") == "1":
        hdr = request.headers.get("x-agenthub-test-clock")
        if hdr:
            hubtime.set_override(hubtime.parse_test_clock(hdr))
        if request.headers.get("x-agenthub-clock-error") == "1":
            hubtime.set_clock_error(True)
    if request.url.path.startswith("/mcp"):
        authz = request.headers.get("authorization") or ""
        token = authz.split(" ", 1)[1].strip() if authz.lower().startswith("bearer ") else ""
        request.state.principal = principal_from_token(token) if token else None
        if request.state.principal is None:
            from hubv1.oauth import www_authenticate

            resp = JSONResponse({"error": "invalid_token", "error_description": "missing or invalid access token"}, status_code=401)
            resp.headers["WWW-Authenticate"] = www_authenticate()
            hubtime.restore_state(*clock_prev)
            return private_headers(resp)
    else:
        request.state.principal = principal_from_http(request.headers.get("authorization"), request.headers.get("cookie"))
        ticket_hdr = (request.headers.get("x-agenthub-upload-ticket") or "").strip()
        if ticket_hdr and (request.state.principal is None or not getattr(request.state.principal, "upload_ticket", None)):
            request.state.principal = principal_from_token(ticket_hdr)
    p = request.state.principal
    ticket = getattr(p, "upload_ticket", None) if p is not None else None
    if ticket:
        uid = ticket.get("upload_id") or ""
        allowed = request.method == "PUT" and request.url.path in {
            f"/api/v1/uploads/{uid}/content",
            f"/api/shared/uploads/{uid}/content",
        }
        if not allowed:
            hubtime.restore_state(*clock_prev)
            return private_headers(JSONResponse({"detail": "forbidden"}, status_code=403))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY:
            hubtime.restore_state(*clock_prev)
            return private_headers(JSONResponse({"detail": "payload too large"}, status_code=413))
    ip = client_ip(request)
    light = {"/", "/health", "/login", "/agent", "/agent/bootstrap.json", "/llms.txt", "/about", "/openapi.json"}
    limit = 120 if request.url.path.startswith("/v1/public") or request.url.path in light else 300
    if not rate_ok(ip, limit):
        hubtime.restore_state(*clock_prev)
        return private_headers(JSONResponse({"detail": "rate limited"}, status_code=429))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        has_bearer = (request.headers.get("authorization") or "").lower().startswith("bearer ")
        if not has_bearer and request.url.path not in {"/session"}:
            if parse_cookie(request.headers.get("cookie", ""), "agenthub_session") and not origin_ok(request):
                hubtime.restore_state(*clock_prev)
                return private_headers(JSONResponse({"detail": "csrf rejected"}, status_code=403))
        if request.url.path == "/session" and not origin_ok(request) and request.headers.get("origin"):
            hubtime.restore_state(*clock_prev)
            return private_headers(JSONResponse({"detail": "csrf rejected"}, status_code=403))
    try:
        response = await call_next(request)
        p = getattr(request.state, "principal", None)
        if p is not None:
            try:
                with v1_connect() as conn:
                    touch_seen(conn, p.id, request.url.path)
            except Exception:
                pass
    except HTTPException:
        hubtime.restore_state(*clock_prev)
        raise
    except Exception:
        hubtime.restore_state(*clock_prev)
        if request.url.path.startswith("/mcp"):
            raise
        return private_headers(JSONResponse({"detail": "internal error"}, status_code=500))
    public = request.url.path in PUBLIC_PATHS or request.url.path.startswith("/v1/public/")
    if public and request.url.path != "/login":
        public_headers(response)
        from hubv1.discovery import DISCOVERY_LINK

        response.headers["Link"] = DISCOVERY_LINK
    else:
        private_headers(response)
    hubtime.restore_state(*clock_prev)
    return response


def get_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Optional[Principal]:
    return principal_from_http(authorization, request.headers.get("cookie"))


def require(*roles: str):
    def dep(p: Optional[Principal] = Depends(get_principal)) -> Principal:
        if p is None:
            raise HTTPException(status_code=401, detail="unauthorized")
        if roles and not any(p.has(r) for r in roles):
            raise HTTPException(status_code=403, detail="forbidden")
        return p

    return dep


class TaskIn(BaseModel):
    type: str = "note"
    title: str = Field(min_length=1, max_length=120)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type")
    @classmethod
    def type_ok(cls, v: str) -> str:
        if v not in TASK_TYPES:
            raise ValueError("unsupported task type")
        return v

    @field_validator("payload")
    @classmethod
    def payload_ok(cls, v: dict[str, Any]) -> dict[str, Any]:
        extra = set(v) - {"body"}
        if extra:
            raise ValueError("unsupported payload fields")
        body = v.get("body", "")
        if not isinstance(body, str) or len(body) > 2000:
            raise ValueError("invalid body")
        return {"body": body} if body else {}


class MessageIn(BaseModel):
    channel: str = Field(default="hub", max_length=40)
    body: str = Field(min_length=1, max_length=2000)

    @field_validator("channel", "body")
    @classmethod
    def no_ctrl(cls, v: str) -> str:
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", v):
            raise ValueError("invalid characters")
        return v


class HeartbeatIn(BaseModel):
    status: str = Field(default="idle", max_length=32)


class ResultIn(BaseModel):
    status: str
    detail: str = Field(default="", max_length=2000)

    @field_validator("status")
    @classmethod
    def status_ok(cls, v: str) -> str:
        if v not in {"completed", "failed"}:
            raise ValueError("unsupported status")
        return v


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


@app.get("/agent", response_class=PlainTextResponse)
def agent_access() -> Response:
    from hubv1.discovery import agent_markdown

    body = agent_markdown()
    return PlainTextResponse(body, media_type="text/markdown; charset=utf-8")


@app.get("/agent/bootstrap.json")
def agent_bootstrap() -> dict[str, Any]:
    from hubv1.discovery import bootstrap

    return bootstrap()


@app.get("/llms.txt", response_class=PlainTextResponse)
def llms_txt() -> Response:
    from hubv1.discovery import llms_txt as body

    return PlainTextResponse(body(), media_type="text/plain; charset=utf-8")


@app.get("/v1/public/summary")
def public_summary() -> dict[str, Any]:
    data = get_public_summary()
    allowed = {
        "hub_available",
        "agents_recent_heartbeat",
        "agents_note",
        "tasks_completed_today",
        "activity_trend_7d",
        "generated_at",
        "heartbeat_interval_seconds",
        "offline_after_seconds",
        "as_of",
        "unavailable_reason",
        "timezone",
        "work_date",
    }
    return {k: v for k, v in data.items() if k in allowed}


@app.get("/.well-known/agenthub.json")
def discovery() -> dict[str, Any]:
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "mcp": f"{PUBLIC_ORIGIN}/mcp/",
        "auth": {"type": "bearer", "login": "/login", "obtain": "owner-provisioned", "mcp": "oauth2-pkce"},
        "public_summary": "/v1/public/summary",
        "agent": "/agent",
        "bootstrap": "/agent/bootstrap.json",
        "openapi": "/openapi.json",
    }


@app.get("/v1/status")
def status(p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "identity": p.id,
        "roles": sorted(p.roles),
        "agents": scoped_agents(p),
        "tasks": scoped_tasks(p, 20),
    }


@app.get("/v1/events")
def events(limit: int = 20, p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {"items": scoped_events(p, limit)}


@app.get("/v1/messages")
def messages(limit: int = 20, p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {"items": scoped_messages(p, limit)}


@app.get("/v1/tasks")
def tasks(limit: int = 20, p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {"items": scoped_tasks(p, limit)}


@app.get("/v1/agents")
def agents(p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {"items": scoped_agents(p)}


@app.get("/v1/logs")
def logs(limit: int = 20, p: Principal = Depends(require("view"))) -> dict[str, Any]:
    return {"items": scoped_events(p, limit)}


@app.post("/v1/tasks", status_code=201)
def create_task(body: TaskIn, p: Principal = Depends(require("dispatch"))) -> dict[str, Any]:
    with db() as conn:
        queued = conn.execute("SELECT COUNT(*) AS n FROM tasks WHERE status='queued'").fetchone()["n"]
        if queued >= MAX_QUEUE:
            raise HTTPException(status_code=429, detail="queue full")
        task_id = str(secrets.token_hex(16))
        now = utcnow_iso()
        conn.execute(
            "INSERT INTO tasks(id, created_at, updated_at, owner_id, assignee_id, type, status, title, payload) VALUES (?,?,?,?,?,?,?,?,?)",
            (task_id, now, now, p.id, None, body.type, "queued", body.title, json.dumps(body.payload, ensure_ascii=False)),
        )
    record_event("task.created", p.id, {"task_id": task_id, "identity_id": p.id, "type": body.type})
    return {"id": task_id, "status": "queued"}


@app.post("/v1/messages", status_code=201)
def create_message(body: MessageIn, p: Principal = Depends(require("dispatch"))) -> dict[str, Any]:
    message_id = str(secrets.token_hex(16))
    with db() as conn:
        conn.execute(
            "INSERT INTO messages(id, created_at, owner_id, sender, channel, body) VALUES (?,?,?,?,?,?)",
            (message_id, utcnow_iso(), p.id, p.id, body.channel, body.body),
        )
    record_event("message.created", p.id, {"message_id": message_id, "identity_id": p.id})
    return {"id": message_id}


@app.post("/v1/agents/me/heartbeat")
def heartbeat(body: HeartbeatIn, p: Principal = Depends(require("report"))) -> dict[str, bool]:
    if p.kind != "agent" and not p.has("manage"):
        raise HTTPException(status_code=403, detail="forbidden")
    with db() as conn:
        conn.execute(
            "INSERT INTO heartbeats(identity_id, received_at) VALUES (?,?)",
            (p.id, utcnow_iso()),
        )
    return {"ok": True}


@app.post("/v1/tasks/{task_id}/result")
def task_result(task_id: str, body: ResultIn, p: Principal = Depends(require("report"))) -> dict[str, str]:
    with db() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not p.has("manage") and row["assignee_id"] != p.id and row["owner_id"] != p.id:
            raise HTTPException(status_code=403, detail="forbidden")
        now = utcnow_iso()
        conn.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?", (body.status, now, task_id))
        if body.status == "completed":
            conn.execute(
                "INSERT OR IGNORE INTO task_completions(task_id, completed_at) VALUES (?,?)",
                (task_id, now),
            )
    record_event("task.result", p.id, {"task_id": task_id, "identity_id": p.id, "status": body.status})
    return {"ok": "true"}


@app.post("/v1/webhooks/github")
async def github_webhook() -> dict[str, str]:
    raise HTTPException(status_code=503, detail="GitHub webhook is disabled")


def _safe_oauth_next(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith("/oauth/authorize"):
        return ""
    if "://" in raw or raw.startswith("//") or "\n" in raw or "\r" in raw or "\\" in raw:
        return ""
    return raw[:2000]


@app.post("/session")
async def login(request: Request) -> Response:
    if request.headers.get("origin") and not origin_ok(request):
        raise HTTPException(status_code=403, detail="csrf rejected")
    ct = request.headers.get("content-type", "")
    token = ""
    nxt = ""
    if "application/json" in ct:
        data = await request.json()
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="invalid body")
        token = str(data.get("token", ""))
        nxt = _safe_oauth_next(str(data.get("next") or ""))
    else:
        form = await request.form()
        token = str(form.get("token", ""))
        nxt = _safe_oauth_next(str(form.get("next") or ""))
    nxt = nxt or _safe_oauth_next(request.query_params.get("next") or "")
    p = principal_from_token(token)
    if p is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    sid = secrets.token_urlsafe(32)
    now = utcnow()
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions(id, identity_id, created_at, expires_at, revoked_at) VALUES (?,?,?,?,?)",
            (sid, p.id, now.isoformat(), (now + timedelta(hours=SESSION_HOURS)).isoformat(), None),
        )
    resp = RedirectResponse(nxt or "/console", status_code=303)
    private_headers(resp)
    record_event("session.login", p.id, {"identity_id": p.id})
    resp.set_cookie(
        "agenthub_session",
        sid,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_HOURS * 3600,
        path="/",
    )
    return resp


@app.post("/session/logout")
def logout(request: Request, p: Principal = Depends(require("view"))) -> Response:
    sid = parse_cookie(request.headers.get("cookie", ""), "agenthub_session")
    if sid:
        with db() as conn:
            conn.execute("UPDATE sessions SET revoked_at=? WHERE id=?", (utcnow_iso(), sid))
    resp = RedirectResponse("/", status_code=303)
    private_headers(resp)
    resp.delete_cookie("agenthub_session", path="/")
    return resp


def page_shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>{html.escape(title)}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #0f1419; color: #e7ecf3; }}
    main {{ max-width: 920px; margin: 0 auto; padding: 28px 16px 48px; }}
    h1 {{ font-size: 1.8rem; margin: 0 0 8px; }}
    .muted {{ color: #9aa7b8; }}
    a {{ color: #7cc4ff; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 16px; }}
    .card {{ background: #18202a; border: 1px solid #2a3644; border-radius: 14px; padding: 16px; }}
    .num {{ font-size: 1.6rem; font-weight: 700; }}
    .pill {{ display: inline-block; background: #1f6feb33; color: #9ecbff; border: 1px solid #388bfd66; border-radius: 999px; padding: 2px 10px; font-size: 12px; }}
    form {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
    input, button {{ border-radius: 10px; border: 1px solid #2a3644; padding: 10px 12px; background: #0f1419; color: #e7ecf3; }}
    button {{ background: #1f6feb; border-color: #1f6feb; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ text-align: left; padding: 8px 6px; border-bottom: 1px solid #2a3644; vertical-align: top; }}
    .bar {{ display: flex; gap: 4px; align-items: flex-end; height: 72px; }}
    .bar i {{ display: block; width: 100%; background: #388bfd; border-radius: 4px 4px 0 0; min-height: 2px; }}
  </style>
</head>
<body><main>{body}</main></body></html>"""


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    s = get_public_summary()
    if s.get("unavailable_reason"):
        hub = "暂时无法获取"
        agents = "暂时无法获取"
        done = "暂时无法获取"
        trend_html = "<p class='muted'>暂时无法获取</p>"
        stamp = html.escape(s.get("generated_at", ""))
    else:
        hub = "可用" if s.get("hub_available") else "不可用"
        if s.get("agents_note") == "尚未接入":
            agents = "尚未接入"
        else:
            agents = str(s.get("agents_recent_heartbeat", 0))
        done = str(s.get("tasks_completed_today", 0))
        trend = s.get("activity_trend_7d") or []
        mx = max([x.get("completed_tasks", 0) for x in trend] + [1])
        bars = "".join(
            f"<div style='flex:1;text-align:center'><i style='height:{8 + int(36 * x.get('completed_tasks',0)/mx)}px'></i><div class='muted' style='font-size:11px'>{html.escape(x.get('date','')[5:])}</div></div>"
            for x in trend
        )
        trend_html = f"<div class='bar'>{bars}</div>"
        stamp = html.escape(s.get("generated_at", ""))
    body = f"""
    <p class="pill">v{APP_VERSION} · public overview</p>
    <h1>Agenthub</h1>
    <p class="muted">公开活跃度概览。资料库、聊天区、工作区和每日工作日志需要认证。对齐摘要不是可执行命令。</p>
    <p class="muted">模块：资料库 · 每日日志 · 聊天区 · 文章工作区。08:00 / 20:00 摘要由本机服务在到期后尝试生成；外部定时唤醒未接入。公共页不含私有项目、成员或附件。</p>
    <div class="grid">
      <div class="card"><div class="muted">Hub</div><div class="num">{html.escape(hub)}</div></div>
      <div class="card"><div class="muted">最近有心跳的 Agent</div><div class="num">{html.escape(str(agents))}</div></div>
      <div class="card"><div class="muted">今日工作日志</div><div class="num">{html.escape(str(done))}</div></div>
    </div>
    <section class="card" style="margin-top:16px">
      <h2 style="margin:0 0 8px;font-size:1.1rem">近 7 天工作日志</h2>
      {trend_html}
      <p class="muted">口径：按北京时间 Asia/Shanghai 的工作日统计日志条数。网页访问、API 查询、MCP 握手不计入。心跳间隔 {HEARTBEAT_INTERVAL}s，超过 {OFFLINE_AFTER}s 视为过期。</p>
      <p class="muted">更新时间 {stamp} · 业务日 {html.escape(s.get('work_date') or '')}</p>
    </section>
    <p style="margin-top:18px"><a href="/agent">持 token 的 Agent 接入</a> · <a href="/about">公开简介</a> · <a href="/login">进入控制台</a></p>
    """
    return page_shell("Agenthub", body)


def _published_public_profile() -> dict[str, Any]:
    from hubv1.store import connect

    with connect() as conn:
        row = conn.execute(
            "SELECT kind, version, title, body, published, created_at FROM profiles WHERE kind='public' AND published=1 ORDER BY version DESC LIMIT 1"
        ).fetchone()
    if not row:
        return {"published": False, "body": "公开简介尚未批准发布。"}
    return dict(row) | {"published": True}


@app.get("/about", response_class=HTMLResponse)
def about() -> str:
    prof = _published_public_profile()
    body = f"""
    <p class="pill">public bio</p>
    <h1>公开简介</h1>
    <pre style="white-space:pre-wrap">{html.escape(prof.get('body') or '')}</pre>
    <p class="muted">协作资料不在本页。持有效 token 的 Agent 可读取协作资料与资料库共享条目，不必上公网。</p>
    <p><a href="/">返回</a></p>
    """
    return page_shell("公开简介", body)


@app.get("/v1/public/profile")
def public_profile() -> dict[str, Any]:
    return _published_public_profile()


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    nxt = _safe_oauth_next(request.query_params.get("next") or "")
    hidden = f'<input type="hidden" name="next" value="{html.escape(nxt)}">' if nxt else ""
    body = f"""
    <p class="pill">console login</p>
    <h1>进入控制台</h1>
    <p class="muted">通过 HTTPS 请求体提交凭据。不会写入地址栏或浏览器脚本存储。</p>
    <form method="post" action="/session" autocomplete="off">
      {hidden}
      <input type="password" name="token" required maxlength="200" placeholder="访问令牌">
      <button type="submit">登录</button>
    </form>
    """
    resp = HTMLResponse(page_shell("登录 Agenthub", body))
    return private_headers(resp)


@app.get("/console", response_class=HTMLResponse)
def console(p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(overview_page(page_shell, p))


@app.get("/console/library", response_class=HTMLResponse)
def console_library(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    q = request.query_params.get("q") or ""
    kind = request.query_params.get("type") or ""
    return private_headers(library_page(page_shell, p, q=q, kind=kind))


@app.get("/console/logs", response_class=HTMLResponse)
def console_logs(p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(logs_page(page_shell, p))


@app.get("/console/chat", response_class=HTMLResponse)
def console_chat(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(chat_page(page_shell, p, thread_id=request.query_params.get("thread") or "", on=request.query_params.get("on") or ""))


@app.get("/console/workspaces", response_class=HTMLResponse)
def console_workspaces(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(agent_workspaces_page(page_shell, p, mine_only=False, err=request.query_params.get("err") or ""))


@app.get("/console/workspaces/me", response_class=HTMLResponse)
def console_my_workspace(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(agent_workspaces_page(page_shell, p, mine_only=True, err=request.query_params.get("err") or ""))


def _console_ws_dest(w: dict, p: Principal) -> str:
    return "/console/workspaces/me" if w["owner_agent_id"] == p.id else "/console/workspaces"


def _console_admin_reason(acc, w, form) -> str:
    reason = str(form.get("admin_reason") or "")
    if acc.manage and acc.p.id != w["owner_agent_id"] and not reason:
        return "console-ui"
    return reason


@app.post("/console/workspaces/{workspace_id}/nodes")
async def console_create_node(workspace_id: str, request: Request, p: Principal = Depends(require("view"))):
    from hubv1.acl import access_for
    from hubv1 import workspace as wsmod

    form = await request.form()
    acc = access_for(p)
    w = wsmod.get_workspace(workspace_id)
    if not w:
        raise HTTPException(status_code=404, detail="not found")
    try:
        wsmod.create_node(
            acc,
            workspace_id=workspace_id,
            parent_id=None,
            name=str(form.get("name") or ""),
            kind="file",
            data=str(form.get("body") or "").encode("utf-8"),
            mime="text/plain; charset=utf-8",
            request_id=getattr(request.state, "request_id", ""),
            admin_reason=_console_admin_reason(acc, w, form),
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="forbidden")
    except Exception as exc:
        dest = _console_ws_dest(w, p) + "?err=" + quote(str(exc)[:200])
        return private_headers(RedirectResponse(dest, status_code=303))
    return private_headers(RedirectResponse(_console_ws_dest(w, p), status_code=303))


@app.post("/console/workspaces/{workspace_id}/uploads")
async def console_upload_node(workspace_id: str, request: Request, p: Principal = Depends(require("view"))):
    from hubv1.acl import access_for
    from hubv1 import workspace as wsmod

    form = await request.form()
    acc = access_for(p)
    w = wsmod.get_workspace(workspace_id)
    if not w:
        raise HTTPException(status_code=404, detail="not found")
    dest = _console_ws_dest(w, p)
    up = form.get("file")
    filename = getattr(up, "filename", "") or ""
    name = Path(filename).name
    if not name or not wsmod.upload_name_ok(name):
        return private_headers(RedirectResponse(dest + "?err=" + quote("bad filename"), status_code=303))
    fileobj = getattr(up, "file", None)
    if fileobj is None:
        return private_headers(RedirectResponse(dest + "?err=" + quote("empty file"), status_code=303))
    try:
        from hubv1.archive import ingest_upload

        ingest_upload(
            acc,
            workspace_id=workspace_id,
            name=name,
            fileobj=fileobj,
            parent_id=None,
            request_id=getattr(request.state, "request_id", ""),
            admin_reason=_console_admin_reason(acc, w, form),
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="forbidden")
    except Exception as exc:
        return private_headers(RedirectResponse(dest + "?err=" + quote(str(exc)[:200]), status_code=303))
    return private_headers(RedirectResponse(dest, status_code=303))


@app.get("/console/workspace", response_class=HTMLResponse)
def console_workspace(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(workspace_page(page_shell, p, article_id=request.query_params.get("article") or ""))


@app.get("/console/publish", response_class=HTMLResponse)
def console_publish(request: Request, p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(publish_page(page_shell, p, err=request.query_params.get("err") or ""))


@app.post("/console/publish/requests")
async def console_publish_request(request: Request, p: Principal = Depends(require("view"))):
    from hubv1.acl import access_for
    from hubv1 import publisher

    form = await request.form()
    acc = access_for(p)
    node_ids = [str(x) for x in form.getlist("node_ids") if str(x).strip()]
    try:
        publisher.create_request(
            acc,
            node_ids=node_ids,
            target_owner=str(form.get("target_owner") or ""),
            repo=str(form.get("repo") or ""),
            branch=str(form.get("branch") or "main"),
            create_repo=str(form.get("create_repo") or "") in {"1", "on", "true", "yes"},
            request_id=getattr(request.state, "request_id", ""),
        )
    except PermissionError as exc:
        return private_headers(RedirectResponse("/console/publish?err=" + quote(str(exc)[:200] or "forbidden"), status_code=303))
    except Exception as exc:
        return private_headers(RedirectResponse("/console/publish?err=" + quote(str(exc)[:200]), status_code=303))
    return private_headers(RedirectResponse("/console/publish", status_code=303))


@app.post("/console/publish/{request_id}/approve")
def console_publish_approve(request_id: str, p: Principal = Depends(require("manage"))):
    from hubv1.acl import access_for
    from hubv1 import publisher

    acc = access_for(p)
    try:
        publisher.decide(acc, request_id, approve=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)[:200])
    return private_headers(RedirectResponse("/console/publish", status_code=303))


@app.post("/console/publish/{request_id}/reject")
def console_publish_reject(request_id: str, p: Principal = Depends(require("manage"))):
    from hubv1.acl import access_for
    from hubv1 import publisher

    acc = access_for(p)
    try:
        publisher.decide(acc, request_id, approve=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)[:200])
    return private_headers(RedirectResponse("/console/publish", status_code=303))


@app.get("/console/access", response_class=HTMLResponse)
def console_access(p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(access_page(page_shell, p))


@app.get("/console/connections", response_class=HTMLResponse)
def console_connections(p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    from hubv1.oauth import connections_page

    return private_headers(connections_page(page_shell, p))


@app.post("/console/connections/{grant_id}/revoke")
def console_revoke_grant(grant_id: str, p: Principal = Depends(require("view"))) -> Response:
    from hubv1 import oauth_store as ost

    rec = ost.get_grant(grant_id)
    if not rec or rec["identity_id"] != p.id and not p.has("manage"):
        raise HTTPException(status_code=404, detail="not found")
    if rec["identity_id"] != p.id and not p.has("manage"):
        raise HTTPException(status_code=403, detail="forbidden")
    ost.revoke_grant(grant_id)
    ost.audit(grant_id=grant_id, identity_id=p.id, action="user_revoke", result="ok")
    return private_headers(RedirectResponse("/console/connections", status_code=303))


@app.get("/console/profile", response_class=HTMLResponse)
def console_profile(p: Optional[Principal] = Depends(get_principal)) -> Response:
    if p is None:
        return private_headers(RedirectResponse("/login", status_code=303))
    if not p.has("view"):
        raise HTTPException(status_code=403, detail="forbidden")
    return private_headers(profile_page(page_shell, p))


@app.post("/console/profile/{kind}")
async def console_profile_save(kind: str, request: Request, p: Principal = Depends(require("manage"))) -> Response:
    from hubv1.acl import access_for
    from hubv1.api import ProfileIn, put_profile

    form = await request.form()
    request.state.principal = p
    expected = form.get("expected_version")
    body = ProfileIn(
        title=str(form.get("title") or "资料"),
        body=str(form.get("body") or ""),
        publish=bool(form.get("publish")),
        expected_version=int(expected) if expected else None,
    )
    put_profile(kind, body, request, access_for(p))
    return private_headers(RedirectResponse("/console/profile", status_code=303))


@app.post("/console/tasks")
async def console_create_task(request: Request, p: Principal = Depends(require("dispatch"))) -> Response:
    form = await request.form()
    title = str(form.get("title", "")).strip()
    body = str(form.get("body", ""))
    create_task(TaskIn(type="note", title=title or "untitled", payload={"body": body} if body else {}), p)
    return private_headers(RedirectResponse("/console", status_code=303))


@app.post("/console/worklogs")
async def console_worklog(request: Request, p: Principal = Depends(require("report"))) -> Response:
    from hubv1.acl import access_for
    from hubv1.events import append_event
    from hubv1.store import dumps as v1dumps
    from hubv1.store import new_id

    form = await request.form()
    pid = str(form.get("project_id", "")).strip()
    acc = access_for(p)
    if not acc.can_write_worklog(pid) and not acc.manage:
        raise HTTPException(status_code=403, detail="forbidden")
    summary = {
        "done": str(form.get("done") or "")[:300],
        "result": str(form.get("result") or "")[:300],
        "blocker": str(form.get("blocker") or "")[:300],
        "next": str(form.get("next") or "")[:300],
    }
    if not any(summary.values()):
        raise HTTPException(status_code=400, detail="empty summary")
    received = hubtime.now_utc()
    with v1_connect() as conn:
        entry_id = new_id("wl")
        seq = append_event(conn, "worklog.append", p.id, {"entry_id": entry_id}, project_id=pid)
        conn.execute(
            """
            INSERT INTO worklog_entries(entry_id, work_date, author_agent_id, project_id, occurred_at, received_at, summary, evidence_refs, verification_status, supersedes, idempotency_key, event_seq, revision)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
            """,
            (
                entry_id,
                hubtime.shanghai_date(received),
                p.id,
                pid,
                received.isoformat(),
                received.isoformat(),
                v1dumps(summary),
                "[]",
                "claimed",
                None,
                secrets.token_hex(12),
                seq,
            ),
        )
    return private_headers(RedirectResponse("/console/logs", status_code=303))


@app.post("/console/chat/{thread_id}")
async def console_chat_post(thread_id: str, request: Request, p: Principal = Depends(require("report"))) -> Response:
    from hubv1.acl import access_for
    from hubv1.events import append_event
    from hubv1.store import dumps as v1dumps
    from hubv1.store import new_id

    form = await request.form()
    acc = access_for(p)
    with v1_connect() as conn:
        th = conn.execute("SELECT * FROM chat_threads WHERE thread_id=?", (thread_id,)).fetchone()
        if not th or not acc.can_chat(th["project_id"], write=True):
            raise HTTPException(status_code=403, detail="forbidden")
        created = hubtime.now_iso()
        local = hubtime.shanghai_date(hubtime.parse_iso(created))
        mid = new_id("msg")
        reply = str(form.get("reply_to") or "") or None
        seq = append_event(conn, "chat.message", p.id, {"message_id": mid, "thread_id": thread_id}, project_id=th["project_id"])
        conn.execute(
            """
            INSERT INTO chat_messages(message_id, thread_id, reply_to, author, body, created_at, acl, pending_owner, mentions, evidence_refs, revision_of, idempotency_key, event_seq, local_date)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                mid,
                thread_id,
                reply,
                p.id,
                str(form.get("body") or "")[:4000],
                created,
                th["acl"],
                1 if form.get("pending_owner") else 0,
                "[]",
                "[]",
                None,
                secrets.token_hex(12),
                seq,
                local,
            ),
        )
    return private_headers(RedirectResponse(f"/console/chat?thread={thread_id}", status_code=303))


@app.post("/console/publish")
async def console_publish(request: Request, p: Principal = Depends(require("manage"))) -> Response:
    from hubv1.acl import access_for as make_access
    from hubv1.api import publish_article

    form = await request.form()
    request.state.principal = p
    aid = str(form.get("article_id") or "")
    publish_article(aid, request, int(form.get("version") or 0), "local-console", make_access(p))
    return private_headers(RedirectResponse(f"/console/workspace?article={aid}", status_code=303))


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException) -> JSONResponse:
    path = getattr(request.url, "path", "") or ""
    if path.startswith("/api/"):
        code = "unauthorized" if exc.status_code == 401 else ("forbidden" if exc.status_code == 403 else "http")
        if exc.status_code == 429:
            code = "rate_limited"
        body = {
            "error": {
                "code": code,
                "message": str(exc.detail)[:300],
                "retryable": exc.status_code in {429, 502, 503, 504},
                "details": {},
            },
            "request_id": getattr(request.state, "request_id", ""),
            "detail": exc.detail,
        }
        return private_headers(JSONResponse(body, status_code=exc.status_code))
    resp = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return private_headers(resp)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, HTTPException):
        return await http_exc(_, exc)
    if isinstance(exc, PermissionError):
        code = 401 if str(exc) == "unauthorized" else 403
        return private_headers(JSONResponse({"detail": str(exc)}, status_code=code))
    return private_headers(JSONResponse({"detail": "internal error"}, status_code=500))


def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    from hubv1.discovery import sanitize_openapi

    schema = get_openapi(title=APP_NAME, version=APP_VERSION, routes=app.routes, description=app.description)
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "token",
    }
    schema["security"] = [{"bearerAuth": []}]
    schema = sanitize_openapi(schema, public_origin=PUBLIC_ORIGIN)
    public_exact = PUBLIC_PATHS | {"/session"}
    for path, methods in (schema.get("paths") or {}).items():
        open_path = path in public_exact or path.startswith("/v1/public/")
        for op in methods.values():
            if not isinstance(op, dict):
                continue
            if open_path:
                op["security"] = []
            else:
                op["security"] = [{"bearerAuth": []}]
                op.setdefault("responses", {})
                op["responses"].setdefault("401", {"description": "需要有效 Bearer token 或会话"})
                op["responses"].setdefault("403", {"description": "已认证但无权（写权限不足、仅本人资料或已撤销）"})
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi
