"""Per-agent workspaces. Read: any authed agent. Write: owner with workspace:write:own, or admin."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from hubv1.flags import flag, flag_int
from hubv1.version import APP_VERSION
from hubv1.store import (
    DATA_DIR,
    WORKSPACE_MAX_FILE_BYTES,
    WORKSPACE_QUOTA_BYTES,
    audit,
    cfg_int,
    connect,
    dumps,
    ensure_dirs,
    new_id,
    sha256_bytes,
)
from hubv1.timeutil import now_iso

NAME_RE = re.compile(r"^[A-Za-z0-9._\u4e00-\u9fff][A-Za-z0-9._\-\u4e00-\u9fff ]{0,158}$")
SLUG_RE = re.compile(r"[^a-z0-9.-]+")
UNSAFE = re.compile(r"[\x00-\x1f\\/]|[.]{2}")


def wsblobs_dir() -> Path:
    ensure_dirs()
    path = DATA_DIR / "wsblobs"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def display_slug_for(agent_id: str) -> str:
    raw = (agent_id or "agent").strip().lower().replace("_", "-")
    slug = SLUG_RE.sub("-", raw).strip("-.") or "agent"
    return slug[:80]


def enabled() -> bool:
    return flag("feature_workspace")


def _write_blob_bytes(blob_id: str, data: bytes) -> str:
    write_blob_iter(blob_id, [data], max_bytes=max(len(data), 1))
    return blob_id


def write_blob_iter(blob_id: str, chunks: Iterable[bytes], *, max_bytes: int) -> tuple[str, int]:
    folder = wsblobs_dir()
    dest = folder / blob_id
    if dest.exists() or dest.is_symlink():
        raise ValueError("blob exists")
    tmp = folder / (blob_id + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(tmp), flags, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise OverflowError("too large")
                digest.update(chunk)
                fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        if dest.is_symlink() or (dest.exists() and not dest.is_file()):
            raise ValueError("unsafe dest")
        os.replace(str(tmp), str(dest))
        try:
            os.chmod(dest, 0o600)
        except Exception:
            pass
        return digest.hexdigest(), size
    except Exception:
        try:
            if fd >= 0:
                os.close(fd)
        except Exception:
            pass
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def iter_fileobj(fileobj, chunk_size: int = 1024 * 1024) -> Iterable[bytes]:
    while True:
        block = fileobj.read(chunk_size)
        if not block:
            break
        yield block


def read_blob_bytes(blob_id: str) -> Optional[bytes]:
    if not blob_id or "/" in blob_id or "\\" in blob_id or ".." in blob_id:
        return None
    path = wsblobs_dir() / blob_id
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.resolve().parent != wsblobs_dir().resolve():
            return None
    except Exception:
        return None
    return path.read_bytes()


def ensure_workspace(conn, agent_id: str, *, actor_id: str = "system") -> dict[str, Any]:
    row = conn.execute("SELECT * FROM workspaces WHERE owner_agent_id=?", (agent_id,)).fetchone()
    if row:
        return dict(row)
    slug = display_slug_for(agent_id)
    clash = conn.execute("SELECT 1 FROM workspaces WHERE display_slug=?", (slug,)).fetchone()
    if clash:
        slug = (slug[:60] + "-" + new_id("s")[-8:]).strip("-")
    wid = new_id("ws")
    test_ids = {"agent-test", "agent-test-short"}
    if agent_id in test_ids:
        quota = flag_int("workspace_quota_bytes_test", WORKSPACE_QUOTA_BYTES)
    else:
        quota = flag_int("workspace_quota_bytes", WORKSPACE_QUOTA_BYTES)
    now = now_iso()
    conn.execute(
        """
        INSERT INTO workspaces(workspace_id, owner_agent_id, display_slug, status, quota_bytes, used_bytes, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (wid, agent_id, slug, "active", quota, 0, now, now),
    )
    root_id = new_id("node")
    conn.execute(
        """
        INSERT INTO workspace_nodes(
          node_id, workspace_id, parent_id, name, kind, current_version_id, revision, deleted_at, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (root_id, wid, None, "", "dir", None, 1, None, now, now),
    )
    conn.execute("UPDATE workspaces SET root_node_id=? WHERE workspace_id=?", (root_id, wid))
    audit(conn, actor_id, "workspace.create", wid, "", f"owner={agent_id}")
    row = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (wid,)).fetchone()
    return dict(row)


def ensure_all_workspaces(conn) -> int:
    n = 0
    try:
        rows = conn.execute("SELECT id FROM identities").fetchall()
    except Exception:
        return 0
    for r in rows:
        ensure_workspace(conn, r["id"])
        n += 1
    return n


def workspace_of(agent_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        ensure_workspace(conn, agent_id)
        row = conn.execute("SELECT * FROM workspaces WHERE owner_agent_id=?", (agent_id,)).fetchone()
    return dict(row) if row else None


def get_workspace(workspace_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (workspace_id,)).fetchone()
    return dict(row) if row else None


def list_workspaces() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT workspace_id, owner_agent_id, display_slug, status, quota_bytes, used_bytes, updated_at FROM workspaces ORDER BY display_slug"
        ).fetchall()
    return [dict(r) for r in rows]


def safe_name(name: str) -> str:
    name = (name or "").strip()
    if not name or name in {".", ".."} or UNSAFE.search(name) or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError("bad name")
    if not NAME_RE.fullmatch(name.replace(" ", "x") if False else name) and not re.fullmatch(
        r"^[A-Za-z0-9._\u4e00-\u9fff][A-Za-z0-9._\-\u4e00-\u9fff ]{0,158}$", name
    ):
        raise ValueError("bad name")
    return name[:160]


def can_read_workspace(acc, ws: dict[str, Any]) -> bool:
    if not acc.is_authed_reader():
        return False
    if acc.p.id == ws["owner_agent_id"] and acc.revoked and not acc.manage:
        return False
    return True


def can_write_workspace(acc, ws: dict[str, Any], *, reason: str = "") -> bool:
    if not enabled():
        return False
    if acc.revoked and not acc.manage:
        return False
    if acc.manage:
        return True
    if acc.p.id != ws["owner_agent_id"]:
        return False
    return acc.has_scope("workspace:write:own")


def _node(conn, node_id: str):
    return conn.execute("SELECT * FROM workspace_nodes WHERE node_id=?", (node_id,)).fetchone()


def get_node(node_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = _node(conn, node_id)
    return dict(row) if row else None


def depth_of(conn, node) -> int:
    n = 0
    seen = set()
    cur = node
    while cur and cur["parent_id"]:
        if cur["node_id"] in seen:
            raise ValueError("cycle")
        seen.add(cur["node_id"])
        cur = _node(conn, cur["parent_id"])
        n += 1
        if n > 64:
            raise ValueError("too deep")
    return n


def used_bytes(conn, workspace_id: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(size_bytes),0) AS n FROM workspace_versions v JOIN workspace_nodes n ON n.node_id=v.node_id WHERE n.workspace_id=?",
        (workspace_id,),
    ).fetchone()
    return int(row["n"] if row else 0)


def node_count(conn, workspace_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM workspace_nodes WHERE workspace_id=? AND deleted_at IS NULL",
        (workspace_id,),
    ).fetchone()
    return int(row["n"] if row else 0)


def guess_mime(name: str) -> str:
    n = (name or "").strip().lower()
    if n.endswith(".tar.gz") or n.endswith(".tgz"):
        return "application/gzip"
    ext = Path(n).suffix
    return {
        ".zip": "application/zip",
        ".tar": "application/x-tar",
        ".gz": "application/gzip",
        ".7z": "application/x-7z-compressed",
        ".md": "text/markdown; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".json": "application/json",
        ".csv": "text/csv; charset=utf-8",
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    }.get(ext, "application/octet-stream")


def upload_name_ok(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n or n.startswith("."):
        return False
    banned = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".com", ".scr", ".js", ".mjs", ".html", ".htm"}
    if Path(n).suffix in banned:
        return False
    if n.endswith(".tar.gz") or n.endswith(".tgz"):
        return True
    return True


def node_relpath(node_id: str) -> str:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node:
            return ""
        rows = conn.execute(
            "SELECT node_id, parent_id, name FROM workspace_nodes WHERE workspace_id=?",
            (node["workspace_id"],),
        ).fetchall()
    return _relpath_from_rows(node_id, [dict(r) for r in rows])


def _relpath_from_rows(node_id: str, rows: list[dict[str, Any]]) -> str:
    by_id = {r["node_id"]: r for r in rows}
    parts: list[str] = []
    seen: set[str] = set()
    cur = by_id.get(node_id)
    while cur and cur.get("name"):
        if cur["node_id"] in seen:
            break
        seen.add(cur["node_id"])
        parts.append(cur["name"])
        pid = cur.get("parent_id")
        cur = by_id.get(pid) if pid else None
        if cur and not cur.get("name"):
            break
    return "/".join(reversed(parts))


def list_files(workspace_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        tree = [dict(r) for r in conn.execute("SELECT node_id, parent_id, name FROM workspace_nodes WHERE workspace_id=?", (workspace_id,))]
        rows = conn.execute(
            """
            SELECT n.node_id, n.workspace_id, n.name, n.kind, n.revision, n.current_version_id, n.updated_at, n.deleted_at,
                   v.size_bytes, v.mime_type, v.sha256
            FROM workspace_nodes n
            LEFT JOIN workspace_versions v ON v.version_id=n.current_version_id
            WHERE n.workspace_id=? AND n.kind='file' AND n.deleted_at IS NULL
            ORDER BY n.name
            """,
            (workspace_id,),
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["path"] = _relpath_from_rows(item["node_id"], tree)
        out.append(item)
    out.sort(key=lambda x: x.get("path") or x["name"])
    return out


def list_children(workspace_id: str, parent_id: Optional[str], *, include_deleted: bool = False) -> list[dict[str, Any]]:
    with connect() as conn:
        if parent_id:
            q = "SELECT * FROM workspace_nodes WHERE workspace_id=? AND parent_id=? "
        else:
            ws = conn.execute("SELECT root_node_id FROM workspaces WHERE workspace_id=?", (workspace_id,)).fetchone()
            parent_id = ws["root_node_id"] if ws else None
            q = "SELECT * FROM workspace_nodes WHERE workspace_id=? AND parent_id=? "
        if not include_deleted:
            q += "AND deleted_at IS NULL "
        q += "ORDER BY kind DESC, name"
        rows = conn.execute(q, (workspace_id, parent_id)).fetchall()
    return [dict(r) for r in rows]


def create_node(
    acc,
    *,
    workspace_id: str,
    parent_id: Optional[str],
    name: str,
    kind: str,
    data: bytes = b"",
    fileobj=None,
    mime: str = "text/plain",
    request_id: str = "",
    admin_reason: str = "",
    empty_ok: bool = True,
) -> dict[str, Any]:
    if kind not in {"file", "dir"}:
        raise ValueError("kind")
    name = safe_name(name)
    if kind == "file" and fileobj is None and not data:
        data = b""
    max_file = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
    if fileobj is None and len(data) > max_file:
        raise OverflowError("too large")
    with connect() as conn:
        ws = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (workspace_id,)).fetchone()
        if not ws:
            raise KeyError("workspace")
        if not can_write_workspace(acc, dict(ws)):
            raise PermissionError("forbidden")
        if acc.manage and acc.p.id != ws["owner_agent_id"] and not admin_reason:
            raise PermissionError("admin reason required")
        parent = _node(conn, parent_id) if parent_id else _node(conn, ws["root_node_id"])
        if not parent or parent["workspace_id"] != workspace_id or parent["kind"] != "dir" or parent["deleted_at"]:
            raise ValueError("parent")
        if depth_of(conn, parent) + 1 > flag_int("workspace_max_depth", 8):
            raise ValueError("too deep")
        if node_count(conn, workspace_id) >= flag_int("workspace_max_nodes", 400):
            raise OverflowError("too many nodes")
        clash = conn.execute(
            "SELECT 1 FROM workspace_nodes WHERE workspace_id=? AND parent_id=? AND name=? AND deleted_at IS NULL",
            (workspace_id, parent["node_id"], name),
        ).fetchone()
        if clash:
            raise FileExistsError("name")
        quota = int(ws["quota_bytes"] or 0) or flag_int("workspace_quota_bytes", WORKSPACE_QUOTA_BYTES)
        used_before = used_bytes(conn, workspace_id)
        now = now_iso()
        node_id = new_id("node")
        ver_id = None
        if kind == "file":
            blob_id = new_id("blob")
            if fileobj is not None:
                try:
                    fileobj.seek(0)
                except Exception:
                    pass
                chunks = iter_fileobj(fileobj)
            else:
                chunks = [data]
            digest, nbytes = write_blob_iter(blob_id, chunks, max_bytes=max_file)
            if nbytes == 0 and not empty_ok:
                try:
                    (wsblobs_dir() / blob_id).unlink(missing_ok=True)
                except Exception:
                    pass
                raise ValueError("empty file")
            if used_before + nbytes > quota:
                try:
                    (wsblobs_dir() / blob_id).unlink(missing_ok=True)
                except Exception:
                    pass
                raise MemoryError("quota")
            conn.execute(
                "INSERT INTO stored_blobs(blob_id, storage_key, sha256, size_bytes, state, created_at) VALUES (?,?,?,?,?,?)",
                (blob_id, blob_id, digest, nbytes, "ready", now),
            )
            ver_id = new_id("ver")
            conn.execute(
                """
                INSERT INTO workspace_versions(version_id, node_id, version_no, blob_id, sha256, size_bytes, mime_type, actor_id, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (ver_id, node_id, 1, blob_id, digest, nbytes, mime or "application/octet-stream", acc.p.id, now),
            )
        conn.execute(
            """
            INSERT INTO workspace_nodes(node_id, workspace_id, parent_id, name, kind, current_version_id, revision, deleted_at, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (node_id, workspace_id, parent["node_id"], name, kind, ver_id, 1, None, now, now),
        )
        used = used_bytes(conn, workspace_id)
        conn.execute("UPDATE workspaces SET used_bytes=?, updated_at=? WHERE workspace_id=?", (used, now, workspace_id))
        audit(
            conn,
            acc.p.id,
            "workspace.node_create",
            node_id,
            request_id,
            admin_reason or "ok",
        )
    return {"node_id": node_id, "workspace_id": workspace_id, "revision": 1, "kind": kind, "name": name, "version_id": ver_id}


def update_file(acc, node_id: str, *, expected_revision: int, data: bytes, mime: str = "", request_id: str = "", admin_reason: str = "") -> dict[str, Any]:
    max_file = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
    if len(data) > max_file:
        raise OverflowError("too large")
    with connect() as conn:
        node = _node(conn, node_id)
        if not node or node["deleted_at"]:
            raise KeyError("not found")
        ws = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (node["workspace_id"],)).fetchone()
        if not can_write_workspace(acc, dict(ws)):
            raise PermissionError("forbidden")
        if acc.manage and acc.p.id != ws["owner_agent_id"] and not admin_reason:
            raise PermissionError("admin reason required")
        if node["kind"] != "file":
            raise ValueError("not a file")
        if int(node["revision"]) != int(expected_revision):
            raise RuntimeError("conflict")
        quota = int(ws["quota_bytes"] or 0) or flag_int("workspace_quota_bytes", WORKSPACE_QUOTA_BYTES)
        if used_bytes(conn, node["workspace_id"]) + len(data) > quota:
            raise MemoryError("quota")
        now = now_iso()
        blob_id = new_id("blob")
        digest = sha256_bytes(data)
        conn.execute(
            "INSERT INTO stored_blobs(blob_id, storage_key, sha256, size_bytes, state, created_at) VALUES (?,?,?,?,?,?)",
            (blob_id, blob_id, digest, len(data), "reserved", now),
        )
        _write_blob_bytes(blob_id, data)
        conn.execute("UPDATE stored_blobs SET state='ready' WHERE blob_id=?", (blob_id,))
        prev = conn.execute(
            "SELECT MAX(version_no) AS n FROM workspace_versions WHERE node_id=?", (node_id,)
        ).fetchone()
        vno = int(prev["n"] or 0) + 1
        ver_id = new_id("ver")
        prev_mime = ""
        prev_vid = node["current_version_id"]
        if prev_vid:
            prev_row = conn.execute(
                "SELECT mime_type FROM workspace_versions WHERE version_id=?",
                (prev_vid,),
            ).fetchone()
            prev_mime = (prev_row["mime_type"] if prev_row else "") or ""
        mime_final = (mime or "").strip() or prev_mime or guess_mime(node["name"]) or "application/octet-stream"
        conn.execute(
            """
            INSERT INTO workspace_versions(version_id, node_id, version_no, blob_id, sha256, size_bytes, mime_type, actor_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (ver_id, node_id, vno, blob_id, digest, len(data), mime_final, acc.p.id, now),
        )
        new_rev = int(node["revision"]) + 1
        cur = conn.execute(
            "UPDATE workspace_nodes SET current_version_id=?, revision=?, updated_at=? WHERE node_id=? AND revision=?",
            (ver_id, new_rev, now, node_id, expected_revision),
        )
        if cur.rowcount != 1:
            raise RuntimeError("conflict")
        used = used_bytes(conn, node["workspace_id"])
        conn.execute("UPDATE workspaces SET used_bytes=?, updated_at=? WHERE workspace_id=?", (used, now, node["workspace_id"]))
        audit(conn, acc.p.id, "workspace.node_update", node_id, request_id, admin_reason or "ok")
    return {"node_id": node_id, "revision": new_rev, "version_id": ver_id, "version_no": vno}


def tombstone(acc, node_id: str, *, expected_revision: int, request_id: str = "", admin_reason: str = "") -> dict[str, Any]:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node or node["deleted_at"]:
            raise KeyError("not found")
        ws = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (node["workspace_id"],)).fetchone()
        if not can_write_workspace(acc, dict(ws)):
            raise PermissionError("forbidden")
        if acc.manage and acc.p.id != ws["owner_agent_id"] and not admin_reason:
            raise PermissionError("admin reason required")
        if node["node_id"] == ws["root_node_id"]:
            raise ValueError("root")
        if int(node["revision"]) != int(expected_revision):
            raise RuntimeError("conflict")
        now = now_iso()
        new_rev = int(node["revision"]) + 1
        cur = conn.execute(
            "UPDATE workspace_nodes SET deleted_at=?, revision=?, updated_at=? WHERE node_id=? AND revision=?",
            (now, new_rev, now, node_id, expected_revision),
        )
        if cur.rowcount != 1:
            raise RuntimeError("conflict")
        audit(conn, acc.p.id, "workspace.node_delete", node_id, request_id, admin_reason or "ok")
    return {"node_id": node_id, "revision": new_rev, "deleted": True}


def restore_node(acc, node_id: str, *, expected_revision: int, request_id: str = "", admin_reason: str = "") -> dict[str, Any]:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node or not node["deleted_at"]:
            raise KeyError("not found")
        ws = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (node["workspace_id"],)).fetchone()
        if not can_write_workspace(acc, dict(ws)):
            raise PermissionError("forbidden")
        if acc.manage and acc.p.id != ws["owner_agent_id"] and not admin_reason:
            raise PermissionError("admin reason required")
        if int(node["revision"]) != int(expected_revision):
            raise RuntimeError("conflict")
        clash = conn.execute(
            "SELECT 1 FROM workspace_nodes WHERE workspace_id=? AND parent_id=? AND name=? AND deleted_at IS NULL AND node_id!=?",
            (node["workspace_id"], node["parent_id"], node["name"], node_id),
        ).fetchone()
        if clash:
            raise FileExistsError("name")
        now = now_iso()
        new_rev = int(node["revision"]) + 1
        cur = conn.execute(
            "UPDATE workspace_nodes SET deleted_at=NULL, revision=?, updated_at=? WHERE node_id=? AND revision=?",
            (new_rev, now, node_id, expected_revision),
        )
        if cur.rowcount != 1:
            raise RuntimeError("conflict")
        audit(conn, acc.p.id, "workspace.node_restore", node_id, request_id, admin_reason or "ok")
    return {"node_id": node_id, "revision": new_rev, "deleted": False}


def move_node(acc, node_id: str, *, parent_id: str, name: Optional[str], expected_revision: int, request_id: str = "", admin_reason: str = "") -> dict[str, Any]:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node or node["deleted_at"]:
            raise KeyError("not found")
        ws = conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (node["workspace_id"],)).fetchone()
        if not can_write_workspace(acc, dict(ws)):
            raise PermissionError("forbidden")
        if acc.manage and acc.p.id != ws["owner_agent_id"] and not admin_reason:
            raise PermissionError("admin reason required")
        if node["node_id"] == ws["root_node_id"]:
            raise ValueError("root")
        if int(node["revision"]) != int(expected_revision):
            raise RuntimeError("conflict")
        dest = _node(conn, parent_id)
        if not dest or dest["workspace_id"] != node["workspace_id"] or dest["kind"] != "dir" or dest["deleted_at"]:
            raise ValueError("parent")
        # cycle: dest cannot be descendant of node
        cur = dest
        seen = set()
        while cur:
            if cur["node_id"] == node_id:
                raise ValueError("cycle")
            if cur["node_id"] in seen:
                break
            seen.add(cur["node_id"])
            cur = _node(conn, cur["parent_id"]) if cur["parent_id"] else None
        new_name = safe_name(name) if name else node["name"]
        clash = conn.execute(
            "SELECT 1 FROM workspace_nodes WHERE workspace_id=? AND parent_id=? AND name=? AND deleted_at IS NULL AND node_id!=?",
            (node["workspace_id"], dest["node_id"], new_name, node_id),
        ).fetchone()
        if clash:
            raise FileExistsError("name")
        if depth_of(conn, dest) + 1 > flag_int("workspace_max_depth", 8):
            raise ValueError("too deep")
        now = now_iso()
        new_rev = int(node["revision"]) + 1
        curu = conn.execute(
            "UPDATE workspace_nodes SET parent_id=?, name=?, revision=?, updated_at=? WHERE node_id=? AND revision=?",
            (dest["node_id"], new_name, new_rev, now, node_id, expected_revision),
        )
        if curu.rowcount != 1:
            raise RuntimeError("conflict")
        audit(conn, acc.p.id, "workspace.node_move", node_id, request_id, admin_reason or "ok")
    return {"node_id": node_id, "revision": new_rev, "parent_id": parent_id, "name": new_name}


def list_versions(node_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT version_id, version_no, sha256, size_bytes, mime_type, actor_id, created_at FROM workspace_versions WHERE node_id=? ORDER BY version_no",
            (node_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def file_payload(node_id: str, version_id: Optional[str] = None) -> tuple[bytes, str, str]:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node:
            raise KeyError("not found")
        vid = version_id or node["current_version_id"]
        ver = conn.execute("SELECT * FROM workspace_versions WHERE version_id=?", (vid,)).fetchone()
        if not ver:
            raise KeyError("not found")
        blob = conn.execute("SELECT * FROM stored_blobs WHERE blob_id=?", (ver["blob_id"],)).fetchone()
    data = read_blob_bytes(blob["storage_key"] if blob else "")
    if data is None:
        raise FileNotFoundError("blob")
    return data, ver["mime_type"] or "application/octet-stream", node["name"]


def file_disk(node_id: str, version_id: Optional[str] = None) -> tuple[Path, str, str]:
    with connect() as conn:
        node = _node(conn, node_id)
        if not node:
            raise KeyError("not found")
        vid = version_id or node["current_version_id"]
        ver = conn.execute("SELECT * FROM workspace_versions WHERE version_id=?", (vid,)).fetchone()
        if not ver:
            raise KeyError("not found")
        blob = conn.execute("SELECT * FROM stored_blobs WHERE blob_id=?", (ver["blob_id"],)).fetchone()
    key = blob["storage_key"] if blob else ""
    path = wsblobs_dir() / key
    try:
        if not key or path.is_symlink() or not path.is_file() or path.resolve().parent != wsblobs_dir().resolve():
            raise FileNotFoundError("blob")
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise FileNotFoundError("blob") from exc
    return path, ver["mime_type"] or "application/octet-stream", node["name"]


def parse_relpath(path: str) -> list[str]:
    from hubv1.archive import _parts

    parts = _parts(path)
    if not parts:
        raise ValueError("bad path")
    return parts


def resolve_path(workspace_id: str, path: str) -> Optional[dict[str, Any]]:
    parts = parse_relpath(path)
    w = get_workspace(workspace_id)
    if not w:
        return None
    parent_id = w["root_node_id"]
    node = None
    for part in parts:
        found = None
        for child in list_children(workspace_id, parent_id):
            if child["name"] == part:
                found = child
                break
        if not found:
            return None
        node = found
        parent_id = found["node_id"]
    return node


def capabilities(acc) -> dict[str, Any]:
    mine = workspace_of(acc.p.id) if acc.is_authed_reader() else None
    write_own = bool(mine and can_write_workspace(acc, mine))
    quota = int((mine or {}).get("quota_bytes") or 0) or flag_int("workspace_quota_bytes", WORKSPACE_QUOTA_BYTES)
    used = int((mine or {}).get("used_bytes") or 0)
    remaining = max(0, quota - used) if quota else None
    pub_req = acc.has_scope("publish:request") or acc.manage
    import_on = enabled()
    return {
        "identity": acc.p.id,
        "identity_id": acc.p.id,
        "workspace_read": acc.is_authed_reader(),
        "workspace_write_own": write_own,
        "workspace_id": mine["workspace_id"] if mine else None,
        "own_workspace_id": mine["workspace_id"] if mine else None,
        "project_write": sorted(acc.project_ids),
        "scopes": sorted(acc.scopes) if not acc.manage else ["*"],
        "chat_write": acc.has_scope("chat:write"),
        "worklog_project_write": acc.has_scope("worklog:write"),
        "publish_request": pub_req,
        "publish_approve": acc.manage,
        "feature_workspace": enabled(),
        "feature_publisher": flag("feature_publisher"),
        "cannot": [
            "shell",
            "terminal",
            "code_runner",
            "orangepi_config",
            "approve_own_publish",
            "vendor_scheduled_wake",
        ],
        "agent_wake": False,
        "independent_backup": flag("feature_independent_backup"),
        "api_version": APP_VERSION,
        "min_client_version": "0.1.0",
        "limits": {
            "upload_bytes": flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES),
            "workspace_quota_bytes": quota,
            "workspace_remaining_bytes": remaining,
            "import_expanded_bytes": remaining,
            "import_members": min(flag_int("import_members", 5000), flag_int("workspace_max_nodes", 400)),
            "context_max_bytes": 16384,
            "proxy_receive_bytes": None,
        },
        "archives": ["zip", "tar", "tar.gz"] if import_on else [],
        "features": {
            "workspace_write_own": write_own,
            "atomic_import": bool(import_on and write_own),
            "resumable_upload": False,
            "binary_upload": bool(write_own and flag("feature_binary_bridge")),
            "oauth": flag("feature_oauth"),
            "mcp_write_text": flag("feature_mcp_write"),
            "publish_request": pub_req and flag("feature_publisher"),
            "publish_approve": acc.manage,
        },
        "links": {
            "context": "/api/v1/context",
            "jobs": "/api/v1/jobs/{id}",
            "me": "/api/v1/me",
        },
        "idempotency_ttl_seconds": flag_int("idempotency_ttl_seconds", 604800),
    }
