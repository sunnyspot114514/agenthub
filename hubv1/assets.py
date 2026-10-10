"""Immutable library assets: hash-named files under data/assets."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from hubv1.store import (
    assets_dir,
    cfg_int,
    connect,
    dumps,
    ensure_dirs,
    sha256_bytes,
    write_canonical,
)
from hubv1.timeutil import now_iso

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff\-]+")


def safe_filename(name: str) -> str:
    base = Path(name or "file.bin").name.replace("\\", "/").split("/")[-1]
    cleaned = SAFE_NAME.sub("_", base).strip("._") or "file.bin"
    return cleaned[:160]


def put_asset(data: bytes) -> str:
    if not data:
        raise ValueError("empty file")
    ensure_dirs()
    digest = sha256_bytes(data)
    dest = assets_dir() / digest
    if dest.is_file():
        return digest
    tmp = dest.with_name(digest + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, dest)
    os.chmod(dest, 0o600)
    return digest


def read_asset(digest: str) -> Optional[bytes]:
    if not HASH_RE.fullmatch(digest or ""):
        return None
    path = assets_dir() / digest
    if not path.is_file():
        return None
    try:
        if path.resolve().parent != assets_dir().resolve():
            return None
    except Exception:
        return None
    return path.read_bytes()


def extract_pdf_text(data: bytes, limit: int = 80000) -> tuple[str, str]:
    """Return (text, text_status). Scanned PDFs become pending_ocr."""
    try:
        from io import BytesIO
        from pypdf import PdfReader

        reader = PdfReader(BytesIO(data))
        parts: list[str] = []
        for page in reader.pages:
            parts.append(page.extract_text() or "")
            if sum(len(p) for p in parts) >= limit:
                break
        text = "\n".join(parts).strip()
        if len(text) < 40:
            return "", "pending_ocr"
        return text[:limit], "extracted"
    except Exception:
        return "", "pending_ocr"


def attach_file_to_item(
    item_id: str,
    data: bytes,
    *,
    filename: str,
    media_type: str,
    actor_id: str,
    max_bytes: Optional[int] = None,
) -> dict[str, Any]:
    with connect() as conn:
        cap = max_bytes if max_bytes is not None else (cfg_int(conn, "single_file_max_bytes") or 8 * 1024 * 1024)
        prev = conn.execute(
            "SELECT * FROM library_items WHERE item_id=? ORDER BY version DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        if not prev:
            raise KeyError("not found")
    if len(data) > cap:
        raise ValueError("too large")
    digest = put_asset(data)
    fname = safe_filename(filename)
    lower = fname.lower()
    if lower.endswith(".md") or (media_type or "").startswith("text/"):
        body = data.decode("utf-8")
        text_status = "extracted"
    elif (media_type or "").endswith("pdf") or lower.endswith(".pdf"):
        extracted, text_status = extract_pdf_text(data)
        body = extracted or (prev["summary"] or "")
        if text_status == "pending_ocr":
            body = (prev["summary"] or "") + "\n\n扫描件已上传原文件，P0 未做 OCR。"
    else:
        body = prev["summary"] or ""
        text_status = "none"
    now = now_iso()
    with connect() as conn:
        prev = conn.execute(
            "SELECT * FROM library_items WHERE item_id=? ORDER BY version DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        ver = int(prev["version"]) + 1
        ref, body_hash = write_canonical("library", item_id, ver, body)
        conn.execute(
            "UPDATE library_items SET superseded_by=? WHERE item_id=? AND version=?",
            (f"{item_id}@v{ver}", item_id, prev["version"]),
        )
        cols = {r[1] for r in conn.execute("PRAGMA table_info(library_items)").fetchall()}
        conn.execute(
            """
            INSERT INTO library_items(
              item_id, version, type, project_id, title, tags, source_ref, source_date, captured_at,
              content_hash, summary, body_ref, acl, review_status, verification_status, created_by, created_at,
              source_url, file_status, size_bytes, media_type, text_status, uploaded_by, uploaded_at,
              file_hash, original_filename
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                ver,
                prev["type"],
                prev["project_id"],
                prev["title"],
                prev["tags"],
                prev["source_ref"],
                prev["source_date"],
                now,
                body_hash,
                prev["summary"],
                ref,
                prev["acl"],
                prev["review_status"],
                prev["verification_status"],
                actor_id,
                now,
                prev["source_url"] if "source_url" in cols else prev["source_ref"],
                "uploaded",
                len(data),
                media_type or "application/pdf",
                text_status,
                actor_id,
                now,
                digest,
                fname,
            ),
        )
        try:
            conn.execute(
                "INSERT INTO library_fts(item_id, version, title, summary, body) VALUES (?,?,?,?,?)",
                (item_id, str(ver), prev["title"], prev["summary"], body[:20000]),
            )
        except Exception:
            pass
    return {
        "item_id": item_id,
        "version": ver,
        "file_status": "uploaded",
        "file_hash": digest,
        "size_bytes": len(data),
        "text_status": text_status,
        "original_filename": fname,
        "downloadable": True,
    }


def create_library_with_file(
    *,
    item_id: str,
    typ: str,
    project_id: str,
    title: str,
    summary: str,
    tags: list[str],
    data: bytes,
    filename: str,
    media_type: str,
    actor_id: str,
    source_ref: str = "",
    review_status: str = "claimed",
    body_extra: str = "",
) -> dict[str, Any]:
    from hubv1.acl import project_acl

    cap = 8 * 1024 * 1024
    with connect() as conn:
        cap = cfg_int(conn, "single_file_max_bytes") or cap
        exists = conn.execute("SELECT 1 FROM library_items WHERE item_id=?", (item_id,)).fetchone()
    if exists:
        return attach_file_to_item(item_id, data, filename=filename, media_type=media_type, actor_id=actor_id, max_bytes=cap)
    if len(data) > cap:
        raise ValueError("too large")
    digest = put_asset(data)
    fname = safe_filename(filename)
    lower = fname.lower()
    if lower.endswith(".md") or (media_type or "").startswith("text/"):
        body = body_extra or data.decode("utf-8")
        text_status = "extracted"
    elif lower.endswith(".pdf") or (media_type or "").endswith("pdf"):
        extracted, text_status = extract_pdf_text(data)
        body = body_extra or extracted or summary
        if text_status == "pending_ocr" and not body_extra:
            body = summary + "\n\n扫描件已上传原文件，P0 未做 OCR。"
    else:
        body = body_extra or summary
        text_status = "extracted" if body else "none"
    now = now_iso()
    acl = dumps(project_acl(project_id, visibility="shared"))
    with connect() as conn:
        ref, body_hash = write_canonical("library", item_id, 1, body)
        conn.execute(
            """
            INSERT INTO library_items(
              item_id, version, type, project_id, title, tags, source_ref, source_date, captured_at,
              content_hash, summary, body_ref, acl, review_status, verification_status, created_by, created_at,
              source_url, file_status, size_bytes, media_type, text_status, uploaded_by, uploaded_at,
              file_hash, original_filename
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                1,
                typ,
                project_id,
                title,
                dumps(tags),
                source_ref,
                None,
                now,
                body_hash,
                summary,
                ref,
                acl,
                review_status,
                "claimed",
                actor_id,
                now,
                source_ref if str(source_ref).lower().startswith("http") else "",
                "uploaded",
                len(data),
                media_type or "application/pdf",
                text_status,
                actor_id,
                now,
                digest,
                fname,
            ),
        )
        try:
            conn.execute(
                "INSERT INTO library_fts(item_id, version, title, summary, body) VALUES (?,?,?,?,?)",
                (item_id, "1", title, summary, body[:20000]),
            )
        except Exception:
            pass
    return {
        "item_id": item_id,
        "version": 1,
        "file_status": "uploaded",
        "file_hash": digest,
        "size_bytes": len(data),
        "text_status": text_status,
        "original_filename": fname,
        "downloadable": True,
    }


def set_library_extracted_text(item_id: str, body: str, actor_id: str, *, summary: Optional[str] = None) -> dict[str, Any]:
    """Keep the uploaded original file; store OCR/markdown as canonical extracted text."""
    now = now_iso()
    with connect() as conn:
        prev = conn.execute(
            "SELECT * FROM library_items WHERE item_id=? ORDER BY version DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        if not prev:
            raise KeyError("not found")
        ver = int(prev["version"]) + 1
        ref, body_hash = write_canonical("library", item_id, ver, body)
        conn.execute(
            "UPDATE library_items SET superseded_by=? WHERE item_id=? AND version=?",
            (f"{item_id}@v{ver}", item_id, prev["version"]),
        )
        conn.execute(
            """
            INSERT INTO library_items(
              item_id, version, type, project_id, title, tags, source_ref, source_date, captured_at,
              content_hash, summary, body_ref, acl, review_status, verification_status, created_by, created_at,
              source_url, file_status, size_bytes, media_type, text_status, uploaded_by, uploaded_at,
              file_hash, original_filename
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                ver,
                prev["type"],
                prev["project_id"],
                prev["title"],
                prev["tags"],
                prev["source_ref"],
                prev["source_date"],
                now,
                body_hash,
                summary or prev["summary"],
                ref,
                prev["acl"],
                prev["review_status"],
                prev["verification_status"],
                actor_id,
                now,
                prev["source_url"] or "",
                prev["file_status"] or "uploaded",
                prev["size_bytes"],
                prev["media_type"] or "application/pdf",
                "extracted",
                actor_id,
                now,
                prev["file_hash"] or "",
                prev["original_filename"] or "",
            ),
        )
        status = prev["file_status"]
        try:
            conn.execute(
                "INSERT INTO library_fts(item_id, version, title, summary, body) VALUES (?,?,?,?,?)",
                (item_id, str(ver), prev["title"], summary or prev["summary"], body[:20000]),
            )
        except Exception:
            pass
    return {"item_id": item_id, "version": ver, "text_status": "extracted", "file_status": status}
