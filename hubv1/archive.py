"""Unpack ZIP/TAR into a workspace. Rejects traversal, git metadata, and encrypted archives."""
from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path
from typing import Any, Optional

from hubv1.flags import flag_int
from hubv1.store import WORKSPACE_MAX_FILE_BYTES
from hubv1 import workspace as ws

SKIP_PARTS = {"__macosx", ".ds_store", "thumbs.db"}


def is_archive(name: str) -> bool:
    n = (name or "").strip().lower()
    return n.endswith(".zip") or n.endswith(".tar") or n.endswith(".tar.gz") or n.endswith(".tgz")


def inspect_archive(name: str, fileobj) -> dict[str, Any]:
    """List members without writing workspace. Nested archives stay ordinary files."""
    try:
        fileobj.seek(0)
    except Exception:
        pass
    lower = (name or "").lower()
    members: list[dict[str, Any]] = []
    skipped: list[str] = []
    seen: dict[str, str] = {}
    if lower.endswith(".zip"):
        try:
            zf = zipfile.ZipFile(fileobj)
        except zipfile.BadZipFile as exc:
            raise ValueError("not a valid zip") from exc
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                raise ValueError("encrypted zip not supported")
            ratio = int(info.file_size or 0) / max(int(info.compress_size or 1), 1)
            if ratio > flag_int("import_max_ratio", 100):
                raise OverflowError("compression ratio")
            filename = info.filename or ""
            if info.is_dir() or filename.endswith("/"):
                continue
            parts = _parts(filename)
            if not parts:
                skipped.append(filename[:160])
                continue
            rel = "/".join(parts)
            key = rel.casefold()
            if key in seen:
                raise ValueError("duplicate path in archive")
            seen[key] = rel
            members.append({"path": rel, "bytes": int(info.file_size or 0), "kind": "file"})
    else:
        try:
            fileobj.seek(0)
        except Exception:
            pass
        try:
            tf = tarfile.open(fileobj=fileobj, mode="r:*")
        except tarfile.TarError as exc:
            raise ValueError("not a valid tar") from exc
        try:
            for member in tf.getmembers():
                if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                    raise ValueError("archive contains link or special file")
                if not member.isfile():
                    continue
                parts = _parts(member.name)
                if not parts:
                    skipped.append((member.name or "")[:160])
                    continue
                rel = "/".join(parts)
                key = rel.casefold()
                if key in seen:
                    raise ValueError("duplicate path in archive")
                seen[key] = rel
                members.append({"path": rel, "bytes": int(member.size or 0), "kind": "file"})
        finally:
            tf.close()
    total = sum(int(m["bytes"]) for m in members)
    max_members = flag_int("import_members", 5000)
    max_depth = flag_int("import_max_depth", 20)
    max_path = flag_int("import_max_path_bytes", 512)
    if len(members) > max_members:
        raise OverflowError("too many members")
    for m in members:
        depth = m["path"].count("/") + 1
        if depth > max_depth:
            raise OverflowError("too deep")
        if len(m["path"].encode("utf-8")) > max_path:
            raise OverflowError("path too long")
    return {
        "members": members,
        "skipped": skipped[:40],
        "file_count": len(members),
        "expanded_bytes": total,
        "manifest_hash": _hash_members(members),
        "rejected": [],
    }


def _hash_members(members: list[dict[str, Any]]) -> str:
    import hashlib
    import json

    raw = json.dumps(members, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def archive_stem(name: str) -> str:
    n = Path(name or "archive").name
    lower = n.lower()
    if lower.endswith(".tar.gz"):
        n = n[:-7]
    elif lower.endswith(".tgz"):
        n = n[:-4]
    else:
        n = Path(n).stem
    try:
        return ws.safe_name(n or "archive")
    except ValueError:
        return "archive"


def _parts(raw: str, *, context: str = "archive") -> Optional[list[str]]:
    text = (raw or "").replace("\\", "/").strip()
    in_archive = context == "archive"
    if not text or text.startswith("/") or text.startswith("~") or (len(text) > 1 and text[1] == ":"):
        raise ValueError("unsafe path in archive" if in_archive else "unsafe path")
    out: list[str] = []
    for part in text.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError("path traversal in archive" if in_archive else "path traversal")
        low = part.lower()
        if low in SKIP_PARTS or low.startswith("__macosx"):
            return None
        if low in {".git"} or low.endswith(".git"):
            raise ValueError("git metadata cannot be imported")
        if low == ".github":
            return None
        if Path(part).suffix.lower() in {".exe", ".dll", ".bat", ".cmd", ".ps1", ".com", ".scr"}:
            raise ValueError("blocked file type")
        if not ws.upload_name_ok(part):
            return None
        out.append(ws.safe_name(part))
    return out or None


def _unique_name(workspace_id: str, parent_id: Optional[str], base: str) -> str:
    taken = {n["name"] for n in ws.list_children(workspace_id, parent_id)}
    if base not in taken:
        return base
    for i in range(2, 80):
        cand = f"{base}-{i}"[:160]
        if cand not in taken:
            return cand
    raise FileExistsError("name")


def _ensure_dir(acc, workspace_id: str, parent_id: Optional[str], name: str, **kw) -> dict[str, Any]:
    for child in ws.list_children(workspace_id, parent_id):
        if child["name"] == name and child["kind"] == "dir" and not child.get("deleted_at"):
            return child
    return ws.create_node(
        acc,
        workspace_id=workspace_id,
        parent_id=parent_id,
        name=name,
        kind="dir",
        request_id=kw.get("request_id", ""),
        admin_reason=kw.get("admin_reason", ""),
    )


def ingest_upload(
    acc,
    *,
    workspace_id: str,
    name: str,
    fileobj,
    parent_id: Optional[str] = None,
    request_id: str = "",
    admin_reason: str = "",
) -> dict[str, Any]:
    if is_archive(name):
        return import_archive(
            acc,
            workspace_id=workspace_id,
            name=name,
            fileobj=fileobj,
            parent_id=parent_id,
            request_id=request_id,
            admin_reason=admin_reason,
        )
    return ws.create_node(
        acc,
        workspace_id=workspace_id,
        parent_id=parent_id,
        name=name,
        kind="file",
        fileobj=fileobj,
        mime=ws.guess_mime(name),
        request_id=request_id,
        admin_reason=admin_reason,
        empty_ok=False,
    )


def import_archive(
    acc,
    *,
    workspace_id: str,
    name: str,
    fileobj,
    parent_id: Optional[str] = None,
    request_id: str = "",
    admin_reason: str = "",
    dest_name: Optional[str] = None,
    wrap_stem: bool = True,
) -> dict[str, Any]:
    w = ws.get_workspace(workspace_id)
    if not w or not ws.can_write_workspace(acc, w):
        raise PermissionError("forbidden")
    try:
        fileobj.seek(0)
    except Exception:
        pass
    if dest_name:
        folder_name = ws.safe_name(dest_name)
        folder = _ensure_dir(
            acc,
            workspace_id,
            parent_id,
            folder_name,
            request_id=request_id,
            admin_reason=admin_reason,
        )
    elif wrap_stem:
        folder_name = _unique_name(workspace_id, parent_id, archive_stem(name))
        folder = _ensure_dir(
            acc,
            workspace_id,
            parent_id,
            folder_name,
            request_id=request_id,
            admin_reason=admin_reason,
        )
    else:
        folder_name = ""
        folder = {"node_id": parent_id} if parent_id else {"node_id": w["root_node_id"]}
    lower = name.lower()
    created: list[dict[str, Any]] = []
    skipped: list[str] = []
    if lower.endswith(".zip"):
        created, skipped = _import_zip(
            acc, workspace_id, fileobj, folder["node_id"], request_id, admin_reason
        )
    else:
        created, skipped = _import_tar(
            acc, workspace_id, fileobj, folder["node_id"], request_id, admin_reason
        )
    if not created:
        raise ValueError("archive had no importable files")
    return {
        "node_id": folder["node_id"],
        "workspace_id": workspace_id,
        "revision": 1,
        "kind": "dir",
        "name": folder_name,
        "extracted": True,
        "file_count": len(created),
        "skipped": skipped[:30],
    }


def _place_file(acc, workspace_id: str, folder_id: str, parts: list[str], fh, request_id: str, admin_reason: str) -> dict[str, Any]:
    parent_id = folder_id
    for d in parts[:-1]:
        parent = _ensure_dir(
            acc,
            workspace_id,
            parent_id,
            d,
            request_id=request_id,
            admin_reason=admin_reason,
        )
        parent_id = parent["node_id"]
    return ws.create_node(
        acc,
        workspace_id=workspace_id,
        parent_id=parent_id,
        name=parts[-1],
        kind="file",
        fileobj=fh,
        mime=ws.guess_mime(parts[-1]),
        request_id=request_id,
        admin_reason=admin_reason,
        empty_ok=True,
    )


def _import_zip(acc, workspace_id: str, fileobj, folder_id: str, request_id: str, admin_reason: str) -> tuple[list, list]:
    max_file = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
    try:
        zf = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile as exc:
        raise ValueError("not a valid zip") from exc
    created, skipped = [], []
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            raise ValueError("encrypted zip not supported")
        filename = info.filename or ""
        if info.is_dir() or filename.endswith("/"):
            continue
        parts = _parts(filename)
        if not parts:
            skipped.append(filename[:160])
            continue
        if info.file_size > max_file:
            raise OverflowError("too large")
        with zf.open(info, "r") as fh:
            created.append(_place_file(acc, workspace_id, folder_id, parts, fh, request_id, admin_reason))
    return created, skipped


def _import_tar(acc, workspace_id: str, fileobj, folder_id: str, request_id: str, admin_reason: str) -> tuple[list, list]:
    max_file = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
    try:
        fileobj.seek(0)
    except Exception:
        pass
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r:*")
    except tarfile.TarError as exc:
        raise ValueError("not a valid tar") from exc
    created, skipped = [], []
    try:
        for member in tf.getmembers():
            if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise ValueError("archive contains link or special file")
            if not member.isfile():
                continue
            parts = _parts(member.name)
            if not parts:
                skipped.append((member.name or "")[:160])
                continue
            if member.size > max_file:
                raise OverflowError("too large")
            fh = tf.extractfile(member)
            if fh is None:
                skipped.append((member.name or "")[:160])
                continue
            with fh:
                created.append(_place_file(acc, workspace_id, folder_id, parts, fh, request_id, admin_reason))
    finally:
        tf.close()
    return created, skipped
