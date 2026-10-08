from __future__ import annotations

import json
import os
from datetime import timedelta
from typing import Any, Optional

from hubv1 import timeutil
from hubv1.events import append_event
from hubv1.store import PROJ_DIR, dumps, ensure_dirs, new_id, sha256_bytes, sha256_text


def live_dates(at=None) -> list[str]:
    today = timeutil.shanghai_date(at)
    yest = (timeutil.slot_cutoff(today, 0) - timedelta(days=1)).date().isoformat()
    return [yest, today]


def local_date_of(created_at: str) -> str:
    return timeutil.shanghai_date(timeutil.parse_iso(created_at))


def archive_path(thread_id: str, local_date: str):
    ensure_dirs()
    folder = PROJ_DIR / "chat" / thread_id
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    return folder / f"{local_date}.md"


def serialize_message(row) -> dict[str, Any]:
    d = dict(row)
    d["mentions"] = json.loads(d.get("mentions") or "[]") if isinstance(d.get("mentions"), str) else (d.get("mentions") or [])
    d["evidence_refs"] = json.loads(d.get("evidence_refs") or "[]") if isinstance(d.get("evidence_refs"), str) else (d.get("evidence_refs") or [])
    d.pop("acl", None)
    d.pop("idempotency_key", None)
    return d


def render_archive_md(thread_id: str, local_date: str, archive_id: str, rows: list[dict[str, Any]]) -> str:
    lines = [
        f"# chat archive {thread_id} {local_date}",
        f"timezone: Asia/Shanghai",
        f"archive_id: {archive_id}",
        f"schema_version: 12",
        f"count: {len(rows)}",
        "",
    ]
    for r in rows:
        utc = r.get("created_at") or ""
        try:
            local = timeutil.parse_iso(utc).astimezone(timeutil.TZ).isoformat()
        except Exception:
            local = utc
        lines.append(f"## {r.get('message_id')}")
        lines.append(f"- author: {r.get('author')}")
        lines.append(f"- event_seq: {r.get('event_seq') or ''}")
        lines.append(f"- utc: {utc}")
        lines.append(f"- local: {local}")
        lines.append(f"- reply_to_id: {r.get('reply_to') or ''}")
        lines.append("")
        lines.append(r.get("body") or "")
        lines.append("")
    return "\n".join(lines) + "\n"


def atomic_write_text(path, text: str) -> str:
    data = text.encode("utf-8")
    digest = sha256_bytes(data)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        dirfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except Exception:
        pass
    os.chmod(path, 0o600)
    return digest


def verify_archive_file(path, digest: str, count: int, ids: set[str]) -> tuple[bool, str]:
    if not path.is_file():
        return False, "missing_file"
    raw = path.read_bytes()
    if sha256_bytes(raw) != digest:
        return False, "hash_mismatch"
    try:
        text = raw.decode("utf-8")
    except Exception:
        return False, "decode_error"
    found = {line[3:].strip() for line in text.splitlines() if line.startswith("## ")}
    if len([ln for ln in text.splitlines() if ln.startswith("## ")]) != count:
        return False, "count_mismatch"
    if found != ids:
        return False, "id_set_mismatch"
    return True, "ok"
