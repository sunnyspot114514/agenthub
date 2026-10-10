"""Read-only GitHub proxy for allowlisted owners. Token never leaves the hub."""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable, Optional
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from hubv1.flags import flag
from hubv1.publisher import REPO_RE, allowed_owners, load_github_token
from hubv1.version import APP_VERSION

API_HOST = "api.github.com"
READ_MAX = 64 * 1024
TREE_MAX = 400
REPO_LIMIT = 80
Transport = Callable[[str, dict[str, str]], tuple[int, bytes]]

_transport: Optional[Transport] = None


def enabled() -> bool:
    return flag("feature_github_read")


def owners() -> list[str]:
    return [o.lower() for o in allowed_owners() if o]


def default_owner() -> str:
    items = owners()
    return items[0] if items else ""


def set_transport(fn: Optional[Transport]) -> None:
    global _transport
    _transport = fn


class _Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        nxt = urlparse(newurl)
        if nxt.scheme != "https" or (nxt.hostname or "").lower() != API_HOST:
            raise PermissionError("github host not allowed")
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


def _api(path: str, token: str = "") -> tuple[int, Any]:
    path = path if path.startswith("/") else "/" + path
    url = f"https://{API_HOST}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Agenthub-GitHub/{APP_VERSION}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if _transport:
        status, raw = _transport(url, headers)
    else:
        opener = build_opener(_Redirect)
        req = Request(url, method="GET", headers=headers)
        try:
            with opener.open(req, timeout=30) as resp:
                status = getattr(resp, "status", 200)
                raw = resp.read(2 * 1024 * 1024)
        except HTTPError as exc:
            return int(exc.code), _decode_json(exc.read() if hasattr(exc, "read") else b"")
        except Exception as exc:
            raise RuntimeError("github unavailable") from exc
    return status, _decode_json(raw)


def _decode_json(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _owner_ok(owner: str) -> bool:
    return (owner or "").strip().lower() in set(owners())


def split_repo(repo: str, owner: str = "") -> tuple[str, str]:
    text = (repo or "").strip().strip("/")
    if text.lower().startswith("https://github.com/"):
        text = text[19:]
    if "/" in text:
        own, name = text.split("/", 1)
        name = name.split("/", 1)[0]
    else:
        own, name = (owner or default_owner()), text
    own = (own or "").strip()
    name = (name or "").strip()
    if not _owner_ok(own):
        raise PermissionError("owner not on allowlist")
    if not REPO_RE.fullmatch(name) or name in {".", ".."}:
        raise ValueError("bad repo name")
    return own, name


def _norm_path(path: str) -> str:
    rel = (path or "").replace("\\", "/").strip("/")
    if not rel or rel in {".", ".."} or ".." in rel.split("/"):
        raise ValueError("bad path")
    if rel.startswith(".git/") or rel == ".git":
        raise ValueError("git metadata not readable")
    return rel


def _redact_text(text: str) -> str:
    return re.sub(
        r"gho_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}",
        "[redacted]",
        text,
    )


def list_repos(acc, *, owner: str = "", limit: int = 40) -> dict[str, Any]:
    if not acc.is_authed_reader():
        raise PermissionError("forbidden")
    if not enabled():
        raise RuntimeError("unavailable")
    own = (owner or default_owner()).strip()
    if not _owner_ok(own):
        raise PermissionError("owner not on allowlist")
    token = load_github_token() or ""
    limit = max(1, min(int(limit or 40), REPO_LIMIT))
    if token:
        status, data = _api(f"/user/repos?affiliation=owner&per_page={limit}&sort=updated", token)
    else:
        status, data = _api(f"/users/{quote(own)}/repos?type=owner&per_page={limit}&sort=updated", "")
    if status == 404:
        raise KeyError("not found")
    if status >= 400:
        raise RuntimeError("github unavailable")
    items = []
    for row in data if isinstance(data, list) else []:
        login = str((row.get("owner") or {}).get("login") or "")
        if login.lower() != own.lower():
            continue
        html = str(row.get("html_url") or "")
        if not html.startswith("https://github.com/"):
            html = f"https://github.com/{login}/{row.get('name')}"
        items.append(
            {
                "repo": f"{login}/{row.get('name')}",
                "private": bool(row.get("private")),
                "description": _redact_text((row.get("description") or "")[:240]),
                "default_branch": row.get("default_branch") or "main",
                "html_url": html,
                "updated_at": row.get("updated_at") or "",
            }
        )
        if len(items) >= limit:
            break
    return {
        "owner": own,
        "authenticated": bool(token),
        "items": items,
        "note": "Read-only. Token stays on the hub. This is not a GitHub write grant.",
    }


def list_files(acc, *, repo: str, ref: str = "", prefix: str = "", limit: int = 50) -> dict[str, Any]:
    if not acc.is_authed_reader():
        raise PermissionError("forbidden")
    if not enabled():
        raise RuntimeError("unavailable")
    owner, name = split_repo(repo)
    token = load_github_token() or ""
    limit = max(1, min(int(limit or 50), TREE_MAX))
    meta_status, meta = _api(f"/repos/{quote(owner)}/{quote(name)}", token)
    if meta_status == 404:
        raise KeyError("not found")
    if meta_status >= 400:
        raise RuntimeError("github unavailable")
    branch = (ref or meta.get("default_branch") or "main").strip()
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch):
        raise ValueError("bad ref")
    status, tree = _api(f"/repos/{quote(owner)}/{quote(name)}/git/trees/{quote(branch)}?recursive=1", token)
    if status == 404:
        raise KeyError("not found")
    if status >= 400:
        raise RuntimeError("github unavailable")
    pref = (prefix or "").replace("\\", "/").strip("/")
    files = []
    truncated = bool(tree.get("truncated"))
    for node in tree.get("tree") or []:
        if node.get("type") != "blob":
            continue
        path = str(node.get("path") or "").replace("\\", "/")
        if pref and not (path == pref or path.startswith(pref + "/")):
            continue
        files.append({"path": path, "size": int(node.get("size") or 0), "sha": node.get("sha") or ""})
        if len(files) >= limit:
            truncated = True
            break
    return {
        "repo": f"{owner}/{name}",
        "ref": branch,
        "prefix": pref,
        "truncated": truncated,
        "items": files,
    }


def read_file(acc, *, repo: str, path: str, ref: str = "", max_bytes: int = 16384) -> dict[str, Any]:
    if not acc.is_authed_reader():
        raise PermissionError("forbidden")
    if not enabled():
        raise RuntimeError("unavailable")
    owner, name = split_repo(repo)
    rel = _norm_path(path)
    token = load_github_token() or ""
    max_bytes = max(256, min(int(max_bytes or 16384), READ_MAX))
    q = f"/repos/{quote(owner)}/{quote(name)}/contents/{quote(rel)}"
    if ref:
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", ref):
            raise ValueError("bad ref")
        q += f"?ref={quote(ref)}"
    status, data = _api(q, token)
    if status == 404:
        raise KeyError("not found")
    if status >= 400:
        raise RuntimeError("github unavailable")
    if not isinstance(data, dict) or data.get("type") != "file":
        raise ValueError("not a file")
    size = int(data.get("size") or 0)
    encoding = data.get("encoding") or ""
    raw = b""
    if encoding == "base64" and data.get("content"):
        try:
            raw = base64.b64decode(data.get("content") or "", validate=False)
        except Exception as exc:
            raise ValueError("file decode") from exc
    truncated = len(raw) > max_bytes or size > max_bytes
    raw = raw[:max_bytes]
    text = ""
    binary = False
    try:
        text = raw.decode("utf-8")
        text = _redact_text(text)
    except Exception:
        binary = True
        text = ""
    html_url = str(data.get("html_url") or "")
    if not html_url.startswith("https://github.com/"):
        html_url = f"https://github.com/{owner}/{name}/blob/{ref or 'HEAD'}/{rel}"
    return {
        "repo": f"{owner}/{name}",
        "path": rel,
        "bytes": size,
        "truncated": truncated,
        "binary": binary,
        "text": "" if binary else text,
        "html_url": html_url,
        "sha": data.get("sha") or "",
    }
