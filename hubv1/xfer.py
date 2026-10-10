"""Two-phase uploads, import preview/jobs, path-addressed files. No GitHub credentials."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

from hubv1.archive import import_archive, inspect_archive, is_archive
from hubv1.flags import flag, flag_int
from hubv1.settings import public_host
from hubv1.store import WORKSPACE_MAX_FILE_BYTES, audit, cfg, connect, data_dir, dumps, loads, new_id, sha256_bytes
from hubv1.timeutil import now, now_iso
from hubv1 import workspace as ws


def uploads_dir() -> Path:
    path = data_dir() / "uploads"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def _upload_path(upload_id: str) -> Path:
    if not upload_id or "/" in upload_id or "\\" in upload_id or ".." in upload_id:
        raise ValueError("bad upload id")
    return uploads_dir() / upload_id


def _own_ws(acc, workspace_id: str):
    w = ws.get_workspace(workspace_id)
    if not w:
        raise KeyError("not found")
    if not ws.can_read_workspace(acc, w):
        raise KeyError("not found")
    return w


def _own_write(acc, workspace_id: str):
    w = _own_ws(acc, workspace_id)
    if not ws.can_write_workspace(acc, w):
        raise PermissionError("forbidden")
    return w


TICKET_PREFIX = "oht_"


def _hash_ticket(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def public_put_url(upload_id: str) -> str:
    host = public_host()
    return f"https://{host}/api/v1/uploads/{upload_id}/content"


def binary_enabled() -> bool:
    return flag("feature_binary_bridge")


def create_upload(acc, *, name: str, nbytes: int, sha256: str, purpose: str = "file") -> dict[str, Any]:
    if not acc.has_scope("workspace:write:own") and not acc.manage:
        raise PermissionError("forbidden")
    max_file = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
    if nbytes < 0 or nbytes > max_file:
        raise OverflowError("too large")
    digest = (sha256 or "").strip().lower()
    if digest in {"", "0" * 64}:
        digest = ""
    elif len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("bad sha256")
    _purge_expired_uploads()
    uid = new_id("up")
    nowt = now_iso()
    exp = (now() + timedelta(hours=2)).astimezone().isoformat()
    with connect() as conn:
        conn.execute(
            """INSERT INTO xfer_uploads(upload_id, actor_id, name, declared_bytes, declared_sha256, purpose, state, expires_at, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (uid, acc.p.id, Path(name).name[:160], nbytes, digest, purpose[:40], "declared", exp, nowt),
        )
        audit(conn, acc.p.id, "xfer.upload_create", uid, "", purpose)
    return {
        "upload_id": uid,
        "staging_id": uid,
        "content_path": f"/api/v1/uploads/{uid}/content",
        "expires_at": exp,
        "state": "declared",
    }


def _purge_expired_uploads() -> None:
    nowt = now_iso()
    with connect() as conn:
        rows = conn.execute(
            "SELECT upload_id FROM xfer_uploads WHERE state='declared' AND expires_at < ?",
            (nowt,),
        ).fetchall()
        conn.execute(
            "UPDATE xfer_uploads SET state='expired' WHERE state='declared' AND expires_at < ?",
            (nowt,),
        )
        try:
            conn.execute(
                "UPDATE upload_tickets SET consumed_at=? WHERE consumed_at IS NULL AND expires_at < ?",
                (nowt, nowt),
            )
        except Exception:
            pass
    for row in rows:
        _purge_upload(row["upload_id"])


def issue_ticket(identity_id: str, upload_id: str) -> tuple[str, str]:
    ttl = flag_int("oauth_upload_ttl_seconds", 1800)
    token = TICKET_PREFIX + secrets.token_urlsafe(32)
    exp = (now() + timedelta(seconds=max(60, ttl))).astimezone().isoformat()
    with connect() as conn:
        conn.execute(
            "INSERT INTO upload_tickets(ticket_hash, upload_id, identity_id, expires_at, consumed_at) VALUES (?,?,?,?,NULL)",
            (_hash_ticket(token), upload_id, identity_id, exp),
        )
    return token, exp


def lookup_ticket(token: str) -> Optional[dict[str, Any]]:
    if not token or not token.startswith(TICKET_PREFIX):
        return None
    digest = _hash_ticket(token)
    nowt = now_iso()
    with connect() as conn:
        try:
            row = conn.execute("SELECT * FROM upload_tickets WHERE ticket_hash=?", (digest,)).fetchone()
        except Exception:
            return None
    if not row or row["consumed_at"] or row["expires_at"] < nowt:
        return None
    return {"upload_id": row["upload_id"], "identity_id": row["identity_id"], "expires_at": row["expires_at"]}


def consume_ticket(token: str) -> None:
    if not token or not token.startswith(TICKET_PREFIX):
        return
    with connect() as conn:
        conn.execute(
            "UPDATE upload_tickets SET consumed_at=? WHERE ticket_hash=? AND consumed_at IS NULL",
            (now_iso(), _hash_ticket(token)),
        )


def consume_upload_tickets(upload_id: str) -> None:
    with connect() as conn:
        try:
            conn.execute(
                "UPDATE upload_tickets SET consumed_at=? WHERE upload_id=? AND consumed_at IS NULL",
                (now_iso(), upload_id),
            )
        except Exception:
            pass


def upload_status(acc, upload_id: str) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM xfer_uploads WHERE upload_id=?", (upload_id,)).fetchone()
    if not row or row["actor_id"] != acc.p.id:
        raise KeyError("not found")
    return {
        "staging_id": row["upload_id"],
        "upload_id": row["upload_id"],
        "name": row["name"],
        "state": row["state"],
        "bytes": row["size_bytes"] or row["declared_bytes"],
        "declared_bytes": row["declared_bytes"],
        "sha256": row["sha256"] or "",
        "expires_at": row["expires_at"],
    }


def put_upload_bytes(acc, upload_id: str, data: bytes, *, content_length: Optional[int] = None) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM xfer_uploads WHERE upload_id=?", (upload_id,)).fetchone()
    if not row or row["actor_id"] != acc.p.id:
        raise KeyError("not found")
    declared = int(row["declared_bytes"])
    if content_length is not None and content_length != declared:
        raise OverflowError("content-length mismatch")
    if len(data) != declared:
        _purge_upload(upload_id)
        with connect() as conn:
            conn.execute("UPDATE xfer_uploads SET state='failed' WHERE upload_id=?", (upload_id,))
        raise OverflowError("size mismatch")
    digest = hashlib.sha256(data).hexdigest()
    declared_hash = (row["declared_sha256"] or "").strip().lower()
    if declared_hash and digest != declared_hash:
        _purge_upload(upload_id)
        with connect() as conn:
            conn.execute("UPDATE xfer_uploads SET state='failed' WHERE upload_id=?", (upload_id,))
        raise ValueError("sha256 mismatch")
    dest = _upload_path(upload_id)
    if dest.is_file() and row["state"] == "ready" and row["sha256"] == digest:
        return {"upload_id": upload_id, "state": "ready", "reused": True, "sha256": digest, "bytes": declared}
    dest.write_bytes(data)
    dest.chmod(0o600)
    with connect() as conn:
        conn.execute(
            "UPDATE xfer_uploads SET state='ready', size_bytes=?, sha256=? WHERE upload_id=?",
            (declared, digest, upload_id),
        )
    return {"upload_id": upload_id, "state": "ready", "reused": False, "sha256": digest, "bytes": declared}


def put_upload_fileobj(acc, upload_id: str, fileobj, *, max_bytes: int) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM xfer_uploads WHERE upload_id=?", (upload_id,)).fetchone()
    if not row or row["actor_id"] != acc.p.id:
        raise KeyError("not found")
    declared = int(row["declared_bytes"])
    dest = _upload_path(upload_id)
    tmp = dest.with_suffix(".tmp")
    h = hashlib.sha256()
    size = 0
    try:
        with open(tmp, "wb") as fh:
            while True:
                chunk = fileobj.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max(declared, max_bytes):
                    raise OverflowError("too large")
                h.update(chunk)
                fh.write(chunk)
        digest = h.hexdigest()
        declared_hash = (row["declared_sha256"] or "").strip().lower()
        if size != declared or (declared_hash and digest != declared_hash):
            raise ValueError("sha256 mismatch" if size == declared else "size mismatch")
        tmp.replace(dest)
        dest.chmod(0o600)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        _purge_upload(upload_id)
        with connect() as conn:
            conn.execute("UPDATE xfer_uploads SET state='failed' WHERE upload_id=?", (upload_id,))
        raise
    digest = h.hexdigest()
    with connect() as conn:
        conn.execute(
            "UPDATE xfer_uploads SET state='ready', size_bytes=?, sha256=? WHERE upload_id=?",
            (size, digest, upload_id),
        )
    return {"upload_id": upload_id, "state": "ready", "reused": False, "sha256": digest, "bytes": size}


def _purge_upload(upload_id: str) -> None:
    try:
        p = _upload_path(upload_id)
        if p.is_file():
            p.unlink()
    except Exception:
        pass


def _ready_upload(acc, upload_id: str):
    with connect() as conn:
        row = conn.execute("SELECT * FROM xfer_uploads WHERE upload_id=?", (upload_id,)).fetchone()
    if not row or row["actor_id"] != acc.p.id:
        raise KeyError("not found")
    if row["state"] != "ready":
        raise ValueError("upload not ready")
    path = _upload_path(upload_id)
    if not path.is_file():
        raise FileNotFoundError("upload blob missing")
    return dict(row), path


def commit_file(acc, workspace_id: str, *, upload_id: str, path: str, if_match: str = "", if_none_match: bool = False) -> dict[str, Any]:
    w = _own_write(acc, workspace_id)
    _row, blob = _ready_upload(acc, upload_id)
    parts = ws.parse_relpath(path)
    existing = ws.resolve_path(workspace_id, path)
    if existing and if_none_match:
        raise FileExistsError("exists")
    if existing and existing.get("kind") == "file" and not if_match:
        raise RuntimeError("conflict")
    if existing and if_match:
        data_now, mime, _name = ws.file_payload(existing["node_id"])
        etag = hashlib.sha256(data_now).hexdigest()
        if etag != if_match.strip().strip('"'):
            raise RuntimeError("conflict")
    parent_id = w["root_node_id"]
    for d in parts[:-1]:
        found = None
        for child in ws.list_children(workspace_id, parent_id):
            if child["name"] == d and child["kind"] == "dir":
                found = child
                break
        if found:
            parent_id = found["node_id"]
            continue
        created = ws.create_node(acc, workspace_id=workspace_id, parent_id=parent_id, name=d, kind="dir")
        parent_id = created["node_id"]
    name = parts[-1]
    with blob.open("rb") as fh:
        if existing and existing["kind"] == "file":
            info = ws.update_file(
                acc,
                existing["node_id"],
                expected_revision=int(existing["revision"]),
                data=blob.read_bytes(),
                mime=ws.guess_mime(name),
            )
        else:
            info = ws.create_node(
                acc,
                workspace_id=workspace_id,
                parent_id=parent_id,
                name=name,
                kind="file",
                fileobj=fh,
                mime=ws.guess_mime(name),
                empty_ok=False,
            )
    info["path"] = path
    info["etag"] = _row["sha256"]
    return info


def preview_import(acc, workspace_id: str, *, upload_id: str, dest: str) -> dict[str, Any]:
    _own_write(acc, workspace_id)
    row, blob = _ready_upload(acc, upload_id)
    if not is_archive(row["name"]):
        raise ValueError("not an archive")
    with blob.open("rb") as fh:
        inspected = inspect_archive(row["name"], fh)
    dest_name = ws.safe_name(dest)
    pid = new_id("prev")
    nowt = now_iso()
    with connect() as conn:
        conn.execute(
            """INSERT INTO xfer_previews(preview_id, upload_id, actor_id, workspace_id, dest, manifest_json, manifest_hash, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (pid, upload_id, acc.p.id, workspace_id, dest_name, dumps(inspected), inspected["manifest_hash"], nowt),
        )
    existing = ws.resolve_path(workspace_id, dest_name)
    return {
        "preview_id": pid,
        "dest": dest_name,
        "root_keep": dest_name,
        "root_strip": dest_name,
        "exists": bool(existing),
        **inspected,
    }


def run_import(
    acc,
    workspace_id: str,
    *,
    preview_id: str,
    manifest_hash: str,
    conflict: str = "fail",
    expected_revision: Optional[int] = None,
) -> dict[str, Any]:
    w = _own_write(acc, workspace_id)
    with connect() as conn:
        prev = conn.execute("SELECT * FROM xfer_previews WHERE preview_id=?", (preview_id,)).fetchone()
    if not prev or prev["actor_id"] != acc.p.id or prev["workspace_id"] != workspace_id:
        raise KeyError("not found")
    if prev["manifest_hash"] != manifest_hash:
        raise RuntimeError("conflict")
    dest = prev["dest"]
    existing = ws.resolve_path(workspace_id, dest)
    if existing and conflict == "fail" and existing["kind"] == "dir":
        kids = ws.list_children(workspace_id, existing["node_id"])
        if kids:
            raise FileExistsError("dest exists")
    row, blob = _ready_upload(acc, prev["upload_id"])
    job_id = new_id("job")
    nowt = now_iso()
    with connect() as conn:
        conn.execute(
            """INSERT INTO xfer_jobs(job_id, actor_id, workspace_id, kind, state, input_hash, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (job_id, acc.p.id, workspace_id, "import", "running", manifest_hash, nowt, nowt),
        )
    try:
        with blob.open("rb") as fh:
            result = import_archive(
                acc,
                workspace_id=workspace_id,
                name=row["name"],
                fileobj=fh,
                dest_name=dest,
                wrap_stem=False,
            )
        state = "succeeded"
        err = ""
    except Exception as exc:
        result = {"ok": False}
        state = "failed"
        err = str(exc)[:300]
    with connect() as conn:
        conn.execute(
            "UPDATE xfer_jobs SET state=?, result_json=?, error=?, updated_at=? WHERE job_id=?",
            (state, dumps(result), err, now_iso(), job_id),
        )
    if state != "succeeded":
        raise ValueError(err or "import failed")
    return {"job_id": job_id, "state": state, "result": result, "workspace_revision": w.get("updated_at")}


def get_job(acc, job_id: str) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM xfer_jobs WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise KeyError("not found")
    if row["actor_id"] != acc.p.id and not acc.manage:
        raise KeyError("not found")
    out = dict(row)
    out["result"] = loads(out.get("result_json") or "{}", {})
    return out


def remember_op(acc, key: str, method: str, target: str, req_hash: str, status: int, body: dict, job_id: str = "") -> None:
    with connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO xfer_ops(identity_id, op_key, method, target, request_hash, status_code, response, job_id, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (acc.p.id, key, method, target, req_hash, status, dumps(body), job_id, now_iso()),
        )


def get_op(acc, key: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM xfer_ops WHERE identity_id=? AND op_key=?",
            (acc.p.id, key),
        ).fetchone()
    return dict(row) if row else None


def list_files_page(acc, workspace_id: str, *, cursor: str = "", limit: int = 50, max_bytes: int = 16384) -> dict[str, Any]:
    w = _own_ws(acc, workspace_id)
    items = ws.list_files(workspace_id)
    start = 0
    if cursor:
        for i, it in enumerate(items):
            if it["node_id"] == cursor:
                start = i + 1
                break
    limit = max(1, min(int(limit or 50), 200))
    page = []
    returned = 0
    next_c = None
    truncated = False
    for it in items[start:]:
        rec = {
            "path": it.get("path") or it["name"],
            "node_id": it["node_id"],
            "size": int(it.get("size_bytes") or 0),
            "sha256": it.get("sha256") or "",
            "media_type": it.get("mime_type") or "application/octet-stream",
            "etag": it.get("sha256") or it.get("current_version_id") or "",
            "revision": it.get("revision"),
        }
        blob = json.dumps(rec, ensure_ascii=False)
        if page and returned + len(blob) > max_bytes:
            truncated = True
            next_c = page[-1]["node_id"]
            break
        page.append(rec)
        returned += len(blob)
        if len(page) >= limit:
            next_c = rec["node_id"] if start + len(page) < len(items) else None
            truncated = start + len(page) < len(items)
            break
    return {
        "workspace_id": w["workspace_id"],
        "items": page,
        "next_cursor": next_c,
        "truncated": truncated,
        "returned_bytes": returned,
    }


def file_content(acc, workspace_id: str, path: str):
    _own_ws(acc, workspace_id)
    node = ws.resolve_path(workspace_id, path)
    if not node or node["kind"] != "file":
        raise KeyError("not found")
    return ws.file_disk(node["node_id"])


def _norm_rel(path: str) -> str:
    return (path or "").replace("\\", "/").strip("/")


def as_id_list(value: Any) -> list[str]:
    if value in (None, "", [], ()):
        return []
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            try:
                value = json.loads(text)
            except Exception:
                value = [part.strip() for part in text.split(",") if part.strip()]
        else:
            value = [part.strip() for part in text.split(",") if part.strip()]
    if not isinstance(value, (list, tuple)):
        raise ValueError("file_ids must be a list")
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        fid = str(item).strip()
        if not fid or fid in seen:
            continue
        seen.add(fid)
        out.append(fid)
    return out


def resolve_publish_root(workspace_id: str, root: str) -> str:
    root = _norm_rel(root)
    if not root:
        return ""
    node = ws.get_node(root)
    if node and node.get("workspace_id") == workspace_id and node.get("kind") == "dir" and not node.get("deleted_at"):
        return _norm_rel(ws.node_relpath(node["node_id"]))
    return root


def strip_publish_root(path: str, root: str) -> str:
    path = _norm_rel(path)
    root = _norm_rel(root)
    if not root:
        return path
    if path == root:
        raise ValueError("publish root is a directory, not a file")
    prefix = root + "/"
    if not path.startswith(prefix):
        raise ValueError("file not under publish root")
    out = path[len(prefix) :]
    if not out or out in {".", ".."} or ".." in Path(out).parts:
        raise ValueError("bad publish path")
    return out


def create_plan(
    acc,
    workspace_id: str,
    *,
    prefix: str,
    repo: str,
    mode: str,
    visibility: str,
    license_id: str,
    copyright_holder: str,
    file_ids: Any = None,
    root: str = "",
) -> dict[str, Any]:
    w = _own_write(acc, workspace_id)
    if mode not in {"create", "update"}:
        raise ValueError("mode")
    if visibility != "public":
        raise ValueError("only public create/update in v1")
    selected: list[tuple[dict[str, Any], str]] = []
    ids = as_id_list(file_ids)
    prefix_n = _norm_rel(prefix)
    if ids:
        for fid in ids:
            node = ws.get_node(fid)
            if not node or node.get("deleted_at") or node.get("kind") != "file":
                raise ValueError(f"node not publishable: {fid}")
            if node["workspace_id"] != workspace_id:
                raise PermissionError("can only publish files from this workspace")
            selected.append((node, ws.node_relpath(fid) or node["name"]))
    elif prefix_n:
        for it in ws.list_files(workspace_id):
            p = _norm_rel(it.get("path") or it["name"])
            if p == prefix_n or p.startswith(prefix_n + "/"):
                selected.append((it, p))
    else:
        raise ValueError("empty selection: pass file_ids or a directory prefix")
    root_n = resolve_publish_root(workspace_id, root) or (prefix_n if not ids else "")
    files = []
    for it, path in selected:
        published = strip_publish_root(path, root_n) if root_n else _norm_rel(path)
        data, mime, _name = ws.file_payload(it["node_id"])
        files.append(
            {
                "node_id": it["node_id"],
                "path": published,
                "source_path": _norm_rel(path),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mime": mime,
                "version_id": it.get("current_version_id"),
            }
        )
    if not files:
        raise ValueError("empty selection")
    snap = {
        "files": files,
        "repo": repo,
        "mode": mode,
        "visibility": visibility,
        "license": license_id,
        "copyright_holder": copyright_holder,
        "workspace_id": workspace_id,
        "workspace_updated_at": w.get("updated_at"),
        "root": root_n,
    }
    raw = json.dumps(snap, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    mh = hashlib.sha256(raw).hexdigest()
    pid = new_id("plan")
    exp = (now() + timedelta(hours=6)).astimezone().isoformat()
    with connect() as conn:
        conn.execute(
            """INSERT INTO publish_plans(plan_id, actor_id, workspace_id, source_json, manifest_hash, repo, mode, expires_at, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (pid, acc.p.id, workspace_id, dumps(snap), mh, repo, mode, exp, now_iso()),
        )
    return {
        "plan_id": pid,
        "manifest_hash": mh,
        "repo": repo,
        "mode": mode,
        "visibility": visibility,
        "license": license_id,
        "copyright_holder": copyright_holder,
        "file_count": len(files),
        "root": root_n,
        "files": [{"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"], "source_path": f["source_path"]} for f in files],
        "expires_at": exp,
        "note": "request queues only; admin must approve before GitHub write",
    }


def request_from_plan(acc, *, plan_id: str, manifest_hash: str, request_id: str = "") -> dict[str, Any]:
    from hubv1 import publisher

    with connect() as conn:
        plan = conn.execute("SELECT * FROM publish_plans WHERE plan_id=?", (plan_id,)).fetchone()
    if not plan or plan["actor_id"] != acc.p.id:
        raise KeyError("not found")
    if plan["manifest_hash"] != manifest_hash:
        raise RuntimeError("conflict")
    snap = loads(plan["source_json"], {})
    owner_repo = (plan["repo"] or "").strip()
    if "/" not in owner_repo:
        raise ValueError("repo must be owner/name")
    owner, repo = owner_repo.split("/", 1)
    planned = snap.get("files") or []
    node_ids = [f["node_id"] for f in planned]
    publish_paths = {f["node_id"]: f.get("path") or "" for f in planned}
    create_repo = plan["mode"] == "create"
    return publisher.create_request(
        acc,
        node_ids=node_ids,
        target_owner=owner,
        repo=repo,
        branch="main",
        create_repo=create_repo,
        request_id=request_id,
        publish_paths=publish_paths,
    )
