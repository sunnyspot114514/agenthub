"""OAuth 2.1 authorization-code + PKCE S256 for MCP.

Issuer/resource are fixed HTTPS origins, never taken from Host or
X-Forwarded-*. Consent uses the existing Agenthub session cookie.
MCP clients use opaque Bearer access tokens only.
"""
from __future__ import annotations

import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from hubv1 import oauth_store as store
from hubv1.acl import access_for
from hubv1.flags import flag
from hubv1.settings import public_host

router = APIRouter()
SCOPE_HELP = {
    "hub:read": "读取本人工作区和按既有规则可读的共享资料（不含 owner 私密数据）",
    "workspace:write:own": "在自己的工作区新增或覆盖文件，不能改他人文件或 Pi 路径",
    "chat:write": "向 Hub 指定共享聊天发送任务相关内容",
    "publish:request": "把明确文件的公开发布计划交给人工审批，不能批准或推送 GitHub",
}
HOST_OK = re.compile(r"^[A-Za-z0-9.-]+$")


def public_origin() -> str:
    return store.issuer()


def mcp_resource() -> str:
    return store.mcp_resource()


def www_authenticate() -> str:
    meta = public_origin() + "/.well-known/oauth-protected-resource/mcp"
    return f'Bearer realm="Agenthub", resource_metadata="{meta}"'


def as_metadata() -> dict[str, Any]:
    origin = public_origin()
    return {
        "issuer": origin,
        "authorization_endpoint": origin + "/oauth/authorize",
        "token_endpoint": origin + "/oauth/token",
        "revocation_endpoint": origin + "/oauth/revoke",
        "registration_endpoint": origin + "/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": list(store.SUPPORTED_SCOPES),
        "authorization_response_iss_parameter_supported": True,
        "revocation_endpoint_auth_methods_supported": ["none"],
        "resource_indicators_supported": True,
    }


def pr_metadata() -> dict[str, Any]:
    origin = public_origin()
    return {
        "resource": mcp_resource(),
        "authorization_servers": [origin],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(store.SUPPORTED_SCOPES),
        "resource_documentation": origin + "/agent",
    }


def no_store(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


def oauth_error(status: int, error: str, desc: str = "") -> JSONResponse:
    body = {"error": error}
    if desc:
        body["error_description"] = desc[:200]
    return no_store(JSONResponse(body, status_code=status))


def host_allowed(request: Request) -> bool:
    host = (request.headers.get("host") or "").split(":")[0].lower()
    expected = public_host().split(":")[0].lower()
    if host in {"localhost", "127.0.0.1", "testserver", expected}:
        return True
    return False


def _private_host(hostname: str) -> bool:
    host = (hostname or "").lower().strip("[]")
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return True
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return True
    return False


def _ip_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _public_connect_ip(hostname: str, port: int) -> str:
    host = (hostname or "").lower().strip("[]")
    if not host or host in {"localhost", "metadata.google.internal"}:
        raise ValueError("cimd private host")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as exc:
        raise ValueError("cimd private host") from exc
    chosen = ""
    for info in infos:
        ip = info[4][0]
        if _ip_blocked(ip):
            raise ValueError("cimd private host")
        if not chosen:
            chosen = ip
    if not chosen:
        raise ValueError("cimd private host")
    return chosen


def _cimd_get(hostname: str, port: int, ip: str, path: str, headers: dict[str, str]) -> tuple[int, bytes]:
    context = ssl.create_default_context()
    sock = socket.create_connection((ip, port), timeout=3)
    try:
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        conn = http.client.HTTPSConnection(hostname, port, timeout=3, context=context)
        conn.sock = ssock
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        raw = resp.read(65_536 + 1)
        conn.close()
        return status, raw
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def fetch_cimd(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("cimd https only")
    if parsed.username or parsed.password:
        raise ValueError("cimd credentials")
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    ip = _public_connect_ip(hostname, port)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Agenthub-OAuth/1.4",
        "Host": hostname,
    }
    status, raw = _cimd_get(hostname, port, ip, path, headers)
    if 300 <= status < 400:
        raise ValueError("cimd redirect")
    if status != 200:
        raise ValueError("cimd status")
    if len(raw) > 65_536:
        raise ValueError("cimd too large")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("cimd json")
    if data.get("client_id") and data.get("client_id") != url:
        raise ValueError("cimd client_id mismatch")
    data["client_id"] = url
    data.setdefault("token_endpoint_auth_method", "none")
    return data


def resolve_client(client_id: str) -> Optional[dict[str, Any]]:
    found = store.get_client(client_id)
    if found:
        return found
    if client_id.startswith("https://"):
        try:
            info = fetch_cimd(client_id)
        except Exception:
            return None
        uris = info.get("redirect_uris") or []
        if not uris or not all(store.redirect_allowed(u) for u in uris):
            return None
        return store.save_client(info)
    return None


def parse_scopes(raw: str) -> list[str]:
    items = [s for s in (raw or "").split() if s]
    if not items:
        return ["hub:read"]
    bad = [s for s in items if s not in store.SUPPORTED_SCOPES]
    if bad:
        raise ValueError("invalid_scope")
    if "hub:read" not in items:
        items = ["hub:read", *items]
    return items


def intersect_scopes(acc, requested: list[str]) -> list[str]:
    out = []
    for s in requested:
        if s == "hub:read" and acc.is_authed_reader():
            out.append(s)
        elif acc.has_scope(s):
            out.append(s)
    if "hub:read" not in out:
        raise PermissionError("need hub:read")
    return out


def callback_url(redirect_uri: str, params: dict[str, str]) -> str:
    parsed = urlparse(redirect_uri)
    q = parsed.query
    extra = urlencode(params)
    query = f"{q}&{extra}" if q else extra
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


def _page_shell(title: str, body: str) -> str:
    from app import page_shell

    return page_shell(title, body)


@router.get("/.well-known/oauth-authorization-server")
def oauth_as_meta(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    if not host_allowed(request):
        return oauth_error(400, "invalid_request", "host mismatch")
    return no_store(JSONResponse(as_metadata()))


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def oauth_pr_meta(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    if not host_allowed(request):
        return oauth_error(400, "invalid_request", "host mismatch")
    return no_store(JSONResponse(pr_metadata()))


@router.get("/oauth/authorize")
async def authorize_get(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    if not host_allowed(request):
        return oauth_error(400, "invalid_request", "host mismatch")
    q = request.query_params
    client_id = (q.get("client_id") or "").strip()
    redirect_uri = (q.get("redirect_uri") or "").strip()
    response_type = (q.get("response_type") or "").strip()
    challenge = (q.get("code_challenge") or "").strip()
    method = (q.get("code_challenge_method") or "").strip()
    state = q.get("state") or ""
    resource = (q.get("resource") or mcp_resource()).strip()
    try:
        scopes = parse_scopes(q.get("scope") or "hub:read")
        resource_n = store.normalize_resource(resource)
    except Exception:
        return oauth_error(400, "invalid_request", "scope or resource")
    if response_type != "code" or method != "S256" or len(challenge) < 43:
        return oauth_error(400, "invalid_request", "PKCE S256 required")
    client = resolve_client(client_id)
    if not client:
        return oauth_error(400, "invalid_client", "unknown client")
    allowed_uris = client.get("redirect_uris") or []
    if redirect_uri not in allowed_uris or not store.redirect_allowed(redirect_uri):
        return oauth_error(400, "invalid_request", "redirect_uri")
    if resource_n not in store.resource_aliases() and resource_n != mcp_resource():
        err = callback_url(redirect_uri, {"error": "invalid_target", "iss": public_origin(), **({"state": state} if state else {})})
        return no_store(RedirectResponse(err, status_code=302))
    p = getattr(request.state, "principal", None)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "state": state,
        "resource": resource_n,
        "scopes": scopes,
        "client_name": client.get("client_name") or client_id,
    }
    pending_id = store.create_pending(client_id, params)
    if p is None:
        next_q = urlencode({"next": str(request.url.path) + "?" + str(request.query_params)})
        resp = RedirectResponse("/login?" + next_q, status_code=303)
        resp.set_cookie("agenthub_oauth_pending", pending_id, httponly=True, secure=True, samesite="lax", max_age=600, path="/")
        return no_store(resp)
    return no_store(_consent_response(p, pending_id, params))


def _consent_response(p, pending_id: str, params: dict[str, Any]) -> Response:
    acc = access_for(p)
    try:
        granted = intersect_scopes(acc, list(params.get("scopes") or ["hub:read"]))
    except PermissionError:
        return HTMLResponse(_page_shell("无法授权", "<p>当前身份没有这些权限。</p>"), status_code=403)
    rows = "".join(
        f"<dt>{html.escape(s)}</dt><dd>{html.escape(SCOPE_HELP.get(s, s))}</dd>" for s in granted
    )
    extra = "".join(f'<input type="hidden" name="scope" value="{html.escape(s)}">' for s in granted)
    body = f"""
    <p class="pill">OAuth 确认</p>
    <h1>连接 Agenthub</h1>
    <p class="muted">只批准你自己发起的 ChatGPT / MCP 连接。浏览器 cookie 只用于本页，不会导出到云 shell。</p>
    <dl class="card">
      <dt>客户端</dt><dd>{html.escape(str(params.get("client_name") or params.get("client_id")))}</dd>
      <dt>身份</dt><dd>{html.escape(p.id)}</dd>
      <dt>资源</dt><dd>{html.escape(params.get("resource") or "")}</dd>
      <dt>期限</dt><dd>连接一直有效，直到你在本站「OAuth 连接」页撤销，或停用该身份。短期 access 由宿主自动刷新，不用按天重新登录。</dd>
      {rows}
    </dl>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="pending_id" value="{html.escape(pending_id)}">
      {extra}
      <button type="submit" name="decision" value="allow">确认连接</button>
      <button type="submit" name="decision" value="deny" style="background:#444">拒绝</button>
    </form>
    """
    resp = HTMLResponse(_page_shell("确认连接 Agenthub", body))
    resp.set_cookie("agenthub_oauth_pending", pending_id, httponly=True, secure=True, samesite="lax", max_age=600, path="/")
    return resp


@router.post("/oauth/authorize")
async def authorize_post(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    p = getattr(request.state, "principal", None)
    if p is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    pending_id = str(form.get("pending_id") or "")
    cookie_pid = request.cookies.get("agenthub_oauth_pending") or ""
    if not pending_id or pending_id != cookie_pid:
        return oauth_error(400, "invalid_request", "pending mismatch")
    pending = store.get_pending(pending_id)
    if not pending:
        return oauth_error(400, "invalid_request", "pending expired")
    params = pending["params"]
    decision = str(form.get("decision") or "deny")
    store.delete_pending(pending_id)
    redirect_uri = params["redirect_uri"]
    state = params.get("state") or ""
    if decision != "allow":
        loc = callback_url(redirect_uri, {"error": "access_denied", "iss": public_origin(), **({"state": state} if state else {})})
        return no_store(RedirectResponse(loc, status_code=302))
    acc = access_for(p)
    requested = [str(s) for s in form.getlist("scope")] or list(params.get("scopes") or ["hub:read"])
    requested = [s for s in requested if s in (params.get("scopes") or requested)]
    try:
        scopes = intersect_scopes(acc, requested)
    except PermissionError:
        loc = callback_url(redirect_uri, {"error": "access_denied", "iss": public_origin(), **({"state": state} if state else {})})
        return no_store(RedirectResponse(loc, status_code=302))
    grant = store.create_grant(
        client_id=params["client_id"],
        identity_id=p.id,
        resource=params["resource"],
        scopes=scopes,
    )
    code = store.issue_code(
        grant_id=grant["grant_id"],
        client_id=params["client_id"],
        identity_id=p.id,
        redirect_uri=redirect_uri,
        resource=params["resource"],
        scopes=scopes,
        code_challenge=params["code_challenge"],
    )
    store.audit(request_id=getattr(request.state, "request_id", ""), grant_id=grant["grant_id"], client_id=params["client_id"], identity_id=p.id, action="consent", result="allow")
    loc = callback_url(redirect_uri, {"code": code, "iss": public_origin(), **({"state": state} if state else {})})
    resp = RedirectResponse(loc, status_code=302)
    resp.delete_cookie("agenthub_oauth_pending", path="/")
    return no_store(resp)


@router.post("/oauth/token")
async def token_post(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    if not host_allowed(request):
        return oauth_error(400, "invalid_request", "host mismatch")
    form = dict(await request.form())
    grant_type = str(form.get("grant_type") or "")
    client_id = str(form.get("client_id") or "")
    client = resolve_client(client_id)
    if not client:
        return oauth_error(401, "invalid_client")
    resource = str(form.get("resource") or mcp_resource())
    try:
        resource_n = store.normalize_resource(resource)
    except Exception:
        return oauth_error(400, "invalid_target")
    if grant_type == "authorization_code":
        code = str(form.get("code") or "")
        verifier = str(form.get("code_verifier") or "")
        redirect_uri = str(form.get("redirect_uri") or "")
        try:
            rec = store.consume_code(code, client_id=client_id, redirect_uri=redirect_uri, resource=resource_n)
        except PermissionError:
            return oauth_error(400, "invalid_grant", "code replay")
        except Exception:
            return oauth_error(400, "invalid_grant")
        if not store.pkce_ok(verifier, rec["code_challenge"]):
            return oauth_error(400, "invalid_grant", "pkce")
        grant = store.get_grant(rec["grant_id"])
        if not grant or grant["revoked_at"]:
            return oauth_error(400, "invalid_grant")
        tokens = store.issue_token_pair(grant)
        store.audit(grant_id=grant["grant_id"], client_id=client_id, identity_id=grant["identity_id"], action="token", result="code")
        return no_store(JSONResponse(tokens))
    if grant_type == "refresh_token":
        refresh = str(form.get("refresh_token") or "")
        hashed = store.hash_token(refresh)
        rec = store.lookup_refresh(refresh)
        if not rec or rec["client_id"] != client_id:
            return oauth_error(400, "invalid_grant")
        extra = str(form.get("scope") or "").split()
        grant = store.get_grant(rec["grant_id"])
        if not grant or grant["revoked_at"]:
            return oauth_error(400, "invalid_grant")
        granted = grant["scopes"] if isinstance(grant["scopes"], list) else []
        if extra and any(s not in granted for s in extra if s):
            return oauth_error(400, "invalid_scope")
        if extra:
            grant = dict(grant)
            grant["scopes"] = [s for s in granted if s in extra] or granted
        try:
            tokens = store.issue_token_pair(grant, consumed_refresh_hash=hashed)
        except PermissionError:
            return oauth_error(400, "invalid_grant", "refresh replay")
        except Exception:
            return oauth_error(400, "invalid_grant")
        store.audit(grant_id=grant["grant_id"], client_id=client_id, identity_id=grant["identity_id"], action="token", result="refresh")
        return no_store(JSONResponse(tokens))
    return oauth_error(400, "unsupported_grant_type")


@router.post("/oauth/revoke")
async def revoke_post(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    form = dict(await request.form())
    token = str(form.get("token") or "")
    client_id = str(form.get("client_id") or "")
    rec = store.lookup_refresh(token) or store.lookup_access(token)
    if rec:
        if client_id and rec.get("client_id") != client_id:
            return no_store(JSONResponse({}, status_code=200))
        store.revoke_family(rec["family_id"], reason="client_revoke")
        store.audit(grant_id=rec.get("grant_id", ""), client_id=rec.get("client_id", ""), identity_id=rec.get("identity_id", ""), action="revoke", result="ok")
    return no_store(JSONResponse({}, status_code=200))


@router.post("/oauth/register")
async def register_post(request: Request):
    if not flag("feature_oauth"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return oauth_error(400, "invalid_client_metadata")
    if not isinstance(body, dict):
        return oauth_error(400, "invalid_client_metadata")
    uris = body.get("redirect_uris") or []
    if not isinstance(uris, list) or len(uris) > 8:
        return oauth_error(400, "invalid_redirect_uri")
    try:
        info = store.register_public_client(
            redirect_uris=[str(u) for u in uris],
            client_name=str(body.get("client_name") or "")[:120],
            client_uri=str(body.get("client_uri") or "")[:300],
        )
    except ValueError:
        return oauth_error(400, "invalid_redirect_uri")
    store.audit(client_id=info["client_id"], action="register", result="ok")
    return no_store(JSONResponse(info, status_code=201))


def connections_page(page_shell, p) -> Response:
    grants = store.list_grants(p.id)
    rows = []
    for g in grants:
        st = "已撤销" if g.get("revoked_at") else "有效"
        client = store.get_client(g["client_id"]) or {}
        name = html.escape(str(client.get("client_name") or g["client_id"]))
        scopes = html.escape(" ".join(g.get("scopes") or []))
        gid = html.escape(g["grant_id"])
        btn = "" if g.get("revoked_at") else f'<form method="post" action="/console/connections/{gid}/revoke"><button type="submit">撤销</button></form>'
        rows.append(f"<tr><td>{name}</td><td>{scopes}</td><td>{st}</td><td>{btn}</td></tr>")
    table = "".join(rows) or "<tr><td colspan=4 class=muted>还没有 OAuth 连接</td></tr>"
    inner = f"""
    <h1>OAuth 连接</h1>
    <p class="muted">撤销会使该客户端的 access 与 refresh 立即失效。网页退出只结束网页会话。</p>
    <table><thead><tr><th>客户端</th><th>范围</th><th>状态</th><th></th></tr></thead><tbody>{table}</tbody></table>
    """
    from hubv1.pages import wrap

    return wrap(page_shell, "OAuth 连接", p, "/console/connections", inner)
