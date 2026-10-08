"""OAuth client/grant/token persistence.

Design adapted from Waishnav/devspace src/oauth-store.ts at commit
531d3f973f09f7b6b4993c9ff58f80a4514b9ba2 (MIT): store only token hashes;
consume the old refresh and insert the new pair in one transaction.

Agenthub additions: identity_id, token family, replay-revoke, idle+absolute
refresh expiry, grant-level revocation. No plaintext tokens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from hubv1.store import connect, dumps, loads, new_id
from hubv1.timeutil import now_iso, now_utc
from hubv1.flags import flag, flag_int

SUPPORTED_SCOPES = ("hub:read", "workspace:write:own", "chat:write", "publish:request")
ACCESS_PREFIX = "oha_"
REFRESH_PREFIX = "ohr_"
CODE_PREFIX = "ohc_"
REFRESH_NEVER = "9999-12-31T00:00:00+00:00"


def refresh_until(seconds: int, now: Optional[datetime] = None) -> str:
    """0 or negative means no calendar expiry; revoke still works."""
    if int(seconds or 0) <= 0:
        return REFRESH_NEVER
    return (_utc(now) + timedelta(seconds=int(seconds))).isoformat()


def refresh_expired(until: str, now: Optional[str] = None) -> bool:
    if not until or until.startswith("9999"):
        return False
    return until < (now or now_iso())


def _utc(dt: Optional[datetime] = None) -> datetime:
    if dt is None:
        dt = now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def enabled() -> bool:
    return flag("feature_oauth")


def issuer() -> str:
    host = ( __import__("os").getenv("AGENTHUB_PUBLIC_HOST") or "agenthub.sunny99.win").strip()
    return f"https://{host}"


def mcp_resource() -> str:
    return issuer().rstrip("/") + "/mcp/"


def resource_aliases() -> set[str]:
    base = issuer().rstrip("/")
    return {base + "/mcp/", base + "/mcp", mcp_resource()}


def normalize_resource(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return mcp_resource()
    parsed = urlparse(raw)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("resource must be https")
    path = parsed.path or "/"
    if path == "/mcp":
        path = "/mcp/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def redirect_hosts() -> list[str]:
    from hubv1.store import cfg, connect as _c

    with _c() as conn:
        raw = cfg(conn, "oauth_redirect_hosts")
    hosts = loads(raw or "[]", [])
    out = []
    for h in hosts:
        h = str(h).strip().lower()
        if h:
            out.append(h)
    for extra in ("localhost", "127.0.0.1"):
        if extra not in out:
            out.append(extra)
    return out


def redirect_allowed(uri: str) -> bool:
    try:
        parsed = urlparse(uri)
    except Exception:
        return False
    if parsed.scheme not in {"https", "http"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return parsed.scheme in {"http", "https"}
    if parsed.scheme != "https":
        return False
    if host in {"0.0.0.0", "169.254.169.254"}:
        return False
    return host in set(redirect_hosts())


def get_client(client_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT client_json FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
    if not row:
        return None
    data = loads(row["client_json"], {})
    return data if isinstance(data, dict) else None


def save_client(info: dict[str, Any]) -> dict[str, Any]:
    cid = info["client_id"]
    method = info.get("token_endpoint_auth_method") or "none"
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO oauth_clients(client_id, client_json, auth_method, issued_at) VALUES (?,?,?,?)",
            (cid, dumps(info), method, now_iso()),
        )
    return info


def register_public_client(*, redirect_uris: list[str], client_name: str = "", client_uri: str = "") -> dict[str, Any]:
    uris = [str(u).strip() for u in redirect_uris if str(u).strip()]
    if not uris or not all(redirect_allowed(u) for u in uris):
        raise ValueError("redirect_uri not allowed")
    info = {
        "client_id": new_id("oauth"),
        "client_id_issued_at": int(_utc().timestamp()),
        "client_name": (client_name or "mcp-client")[:120],
        "client_uri": (client_uri or "")[:300],
        "redirect_uris": uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "code_challenge_methods": ["S256"],
    }
    return save_client(info)


def create_pending(client_id: str, params: dict[str, Any], ttl_seconds: int = 600) -> str:
    pid = new_id("pend")
    exp = (_utc() + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        conn.execute(
            "INSERT INTO oauth_pending(pending_id, client_id, params_json, expires_at, created_at) VALUES (?,?,?,?,?)",
            (pid, client_id, dumps(params), exp, now_iso()),
        )
    return pid


def get_pending(pending_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM oauth_pending WHERE pending_id=?", (pending_id,)).fetchone()
    if not row:
        return None
    if row["expires_at"] < now_iso():
        return None
    d = dict(row)
    d["params"] = loads(d.pop("params_json"), {})
    return d


def delete_pending(pending_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM oauth_pending WHERE pending_id=?", (pending_id,))


def issue_code(
    *,
    grant_id: str,
    client_id: str,
    identity_id: str,
    redirect_uri: str,
    resource: str,
    scopes: list[str],
    code_challenge: str,
) -> str:
    code = mint(CODE_PREFIX)
    ttl = flag_int("oauth_code_ttl_seconds", 120)
    exp = (_utc() + timedelta(seconds=ttl)).isoformat()
    with connect() as conn:
        conn.execute(
            """INSERT INTO oauth_codes(code_hash, grant_id, client_id, identity_id, redirect_uri, resource, scopes, code_challenge, expires_at, consumed_at)
               VALUES (?,?,?,?,?,?,?,?,?,NULL)""",
            (hash_token(code), grant_id, client_id, identity_id, redirect_uri, resource, dumps(scopes), code_challenge, exp),
        )
    return code


def consume_code(code: str, *, client_id: str, redirect_uri: str, resource: str) -> dict[str, Any]:
    hashed = hash_token(code)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM oauth_codes WHERE code_hash=?", (hashed,)).fetchone()
        if not row:
            raise KeyError("invalid_grant")
        if row["consumed_at"]:
            raise PermissionError("replay")
        if row["expires_at"] < now_iso() or row["client_id"] != client_id:
            raise KeyError("invalid_grant")
        if row["redirect_uri"] != redirect_uri:
            raise KeyError("invalid_grant")
        if normalize_resource(row["resource"]) != normalize_resource(resource):
            raise KeyError("invalid_grant")
        conn.execute("UPDATE oauth_codes SET consumed_at=? WHERE code_hash=?", (now_iso(), hashed))
        data = dict(row)
    data["scopes"] = loads(data["scopes"], [])
    return data


def create_grant(*, client_id: str, identity_id: str, resource: str, scopes: list[str]) -> dict[str, Any]:
    idle = flag_int("oauth_refresh_idle_seconds", 0)
    abs_s = flag_int("oauth_refresh_absolute_seconds", 0)
    now = _utc()
    gid = new_id("grant")
    fid = new_id("fam")
    rec = {
        "grant_id": gid,
        "client_id": client_id,
        "identity_id": identity_id,
        "resource": normalize_resource(resource),
        "scopes": list(scopes),
        "family_id": fid,
        "refresh_idle_until": refresh_until(idle, now),
        "refresh_absolute_until": refresh_until(abs_s, now),
        "revoked_at": None,
        "created_at": now.isoformat(),
    }
    with connect() as conn:
        conn.execute(
            """INSERT INTO oauth_grants(grant_id, client_id, identity_id, resource, scopes, family_id, refresh_idle_until, refresh_absolute_until, revoked_at, created_at)
               VALUES (?,?,?,?,?,?,?,?,NULL,?)""",
            (gid, client_id, identity_id, rec["resource"], dumps(scopes), fid, rec["refresh_idle_until"], rec["refresh_absolute_until"], rec["created_at"]),
        )
    return rec


def get_grant(grant_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM oauth_grants WHERE grant_id=?", (grant_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["scopes"] = loads(d["scopes"], [])
    return d


def list_grants(identity_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM oauth_grants WHERE identity_id=? ORDER BY created_at DESC",
            (identity_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["scopes"] = loads(d["scopes"], [])
        out.append(d)
    return out


def revoke_family(family_id: str, *, reason: str = "revoked") -> None:
    now = now_iso()
    with connect() as conn:
        conn.execute("UPDATE oauth_grants SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL", (now, family_id))
        conn.execute("UPDATE oauth_access_tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL", (now, family_id))
        conn.execute(
            "UPDATE oauth_refresh_tokens SET revoked_at=?, consumed_at=COALESCE(consumed_at, ?) WHERE family_id=? AND revoked_at IS NULL",
            (now, now, family_id),
        )
        conn.execute(
            "INSERT INTO oauth_audit(created_at, grant_id, action, result) VALUES (?,?,?,?)",
            (now, family_id, "family_revoke", reason[:80]),
        )


def revoke_grant(grant_id: str) -> None:
    g = get_grant(grant_id)
    if not g:
        return
    revoke_family(g["family_id"], reason="grant_revoke")


def issue_token_pair(grant: dict[str, Any], *, consumed_refresh_hash: Optional[str] = None) -> dict[str, Any]:
    access = mint(ACCESS_PREFIX)
    refresh = mint(REFRESH_PREFIX)
    now = _utc()
    access_ttl = flag_int("oauth_access_ttl_seconds", 900)
    access_exp = (now + timedelta(seconds=access_ttl)).isoformat()
    idle_exp = grant["refresh_idle_until"]
    abs_exp = grant["refresh_absolute_until"]
    scopes = dumps(grant["scopes"] if isinstance(grant["scopes"], list) else loads(grant["scopes"], []))
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        g = conn.execute("SELECT * FROM oauth_grants WHERE grant_id=?", (grant["grant_id"],)).fetchone()
        if not g or g["revoked_at"]:
            raise PermissionError("grant_revoked")
        if consumed_refresh_hash:
            row = conn.execute("SELECT * FROM oauth_refresh_tokens WHERE token_hash=?", (consumed_refresh_hash,)).fetchone()
            if not row:
                raise KeyError("invalid_grant")
            if row["consumed_at"] or row["revoked_at"]:
                conn.execute("COMMIT")
                revoke_family(row["family_id"], reason="refresh_replay")
                raise PermissionError("replay")
            if refresh_expired(row["idle_expires_at"], now.isoformat()) or refresh_expired(row["absolute_expires_at"], now.isoformat()):
                raise KeyError("invalid_grant")
            n = conn.execute(
                "UPDATE oauth_refresh_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND revoked_at IS NULL",
                (now.isoformat(), consumed_refresh_hash),
            ).rowcount
            if n != 1:
                conn.execute("COMMIT")
                revoke_family(row["family_id"], reason="refresh_race")
                raise PermissionError("replay")
        idle = flag_int("oauth_refresh_idle_seconds", 0)
        new_idle = refresh_until(idle, now)
        if abs_exp and not abs_exp.startswith("9999") and new_idle > abs_exp:
            new_idle = abs_exp
        conn.execute("UPDATE oauth_grants SET refresh_idle_until=? WHERE grant_id=?", (new_idle, grant["grant_id"]))
        conn.execute(
            """INSERT INTO oauth_access_tokens(token_hash, grant_id, family_id, client_id, identity_id, resource, scopes, expires_at, revoked_at)
               VALUES (?,?,?,?,?,?,?,?,NULL)""",
            (hash_token(access), grant["grant_id"], grant["family_id"], grant["client_id"], grant["identity_id"], grant["resource"], scopes, access_exp),
        )
        conn.execute(
            """INSERT INTO oauth_refresh_tokens(token_hash, grant_id, family_id, client_id, identity_id, resource, scopes, idle_expires_at, absolute_expires_at, consumed_at, revoked_at)
               VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL)""",
            (hash_token(refresh), grant["grant_id"], grant["family_id"], grant["client_id"], grant["identity_id"], grant["resource"], scopes, new_idle, abs_exp),
        )
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "scope": " ".join(grant["scopes"] if isinstance(grant["scopes"], list) else loads(grant["scopes"], [])),
    }


def lookup_access(token: str) -> Optional[dict[str, Any]]:
    if not token or not token.startswith(ACCESS_PREFIX):
        return None
    hashed = hash_token(token)
    with connect() as conn:
        row = conn.execute("SELECT * FROM oauth_access_tokens WHERE token_hash=?", (hashed,)).fetchone()
        if not row:
            return None
        grant = conn.execute("SELECT * FROM oauth_grants WHERE grant_id=?", (row["grant_id"],)).fetchone()
    now = now_iso()
    if not grant or grant["revoked_at"] or row["revoked_at"] or row["expires_at"] < now:
        return None
    d = dict(row)
    d["scopes"] = loads(d["scopes"], [])
    d["identity_id"] = grant["identity_id"]
    d["resource"] = grant["resource"]
    return d


def lookup_refresh(token: str) -> Optional[dict[str, Any]]:
    if not token or not token.startswith(REFRESH_PREFIX):
        return None
    hashed = hash_token(token)
    with connect() as conn:
        row = conn.execute("SELECT * FROM oauth_refresh_tokens WHERE token_hash=?", (hashed,)).fetchone()
    if not row:
        return None
    return dict(row)


def audit(*, request_id: str = "", grant_id: str = "", client_id: str = "", identity_id: str = "", action: str, result: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO oauth_audit(created_at, request_id, grant_id, client_id, identity_id, action, result) VALUES (?,?,?,?,?,?,?)",
            (now_iso(), request_id[:32], grant_id[:80], client_id[:80], identity_id[:80], action[:40], result[:80]),
        )


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    import base64

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_ok(verifier: str, challenge: str) -> bool:
    if not verifier or len(verifier) < 43 or len(verifier) > 128:
        return False
    try:
        calc = pkce_s256(verifier)
    except Exception:
        return False
    return hmac.compare_digest(calc, challenge)
