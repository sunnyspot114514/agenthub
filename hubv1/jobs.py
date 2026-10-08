from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Optional

from hubv1 import timeutil
from hubv1.chat import archive_path, atomic_write_text, live_dates, render_archive_md, verify_archive_file
from hubv1.store import connect, dumps, new_id, sha256_text


def _now() -> str:
    return timeutil.now_iso()


def try_lease(conn, job_key: str, ttl_sec: int = 60) -> Optional[str]:
    token = new_id("lease")
    now = timeutil.now()
    until = (now + timedelta(seconds=ttl_sec)).astimezone(timeutil.UTC).isoformat()
    row = conn.execute("SELECT * FROM job_runs WHERE job_key=?", (job_key,)).fetchone()
    if row and row["status"] == "completed":
        return None
    if row and row["lease_until"] and row["status"] == "leased":
        try:
            if timeutil.parse_iso(row["lease_until"]) > now.astimezone(timeutil.UTC):
                return None
        except Exception:
            pass
    conn.execute(
        """
        INSERT INTO job_runs(job_key, lease_token, lease_until, status, snapshot, result, attempt, updated_at)
        VALUES (?,?,?,?,?,?,1,?)
        ON CONFLICT(job_key) DO UPDATE SET
          lease_token=excluded.lease_token,
          lease_until=excluded.lease_until,
          status='leased',
          attempt=job_runs.attempt+1,
          updated_at=excluded.updated_at
        """,
        (job_key, token, until, "leased", "", "", _now()),
    )
    cur = conn.execute("SELECT lease_token, status FROM job_runs WHERE job_key=?", (job_key,)).fetchone()
    if not cur or cur["lease_token"] != token or cur["status"] == "completed":
        return None
    return token


def archive_due_dates(at=None) -> list[str]:
    today = timeutil.shanghai_date(at)
    yest = (timeutil.slot_cutoff(today, 0) - timedelta(days=1)).date().isoformat()
    # dates strictly before yesterday
    return []  # filled from messages


def run_chat_archives() -> dict[str, Any]:
    """Archive local_date < yesterday. Failures leave messages live."""
    done, failed = [], []
    with connect() as conn:
        threads = [r["thread_id"] for r in conn.execute("SELECT thread_id FROM chat_threads").fetchall()]
        cutoff = live_dates()[0]  # yesterday
    for tid in threads:
        with connect() as conn:
            dates = [
                r["local_date"]
                for r in conn.execute(
                    "SELECT DISTINCT local_date FROM chat_messages WHERE thread_id=? AND local_date<? AND (archive_id IS NULL OR archive_id='') ORDER BY local_date",
                    (tid, cutoff),
                ).fetchall()
                if r["local_date"]
            ]
        for day in dates:
            try:
                info = archive_thread_date(tid, day)
                if info.get("ok"):
                    done.append(info)
                else:
                    failed.append(info)
            except Exception as exc:
                failed.append({"thread_id": tid, "local_date": day, "error": type(exc).__name__, "ok": False})
    return {"archived": done, "failed": failed}


def archive_thread_date(thread_id: str, local_date: str) -> dict[str, Any]:
    job_key = f"archive:{thread_id}:{local_date}"
    with connect() as conn:
        existing = conn.execute(
            "SELECT * FROM chat_archives WHERE thread_id=? AND local_date=?",
            (thread_id, local_date),
        ).fetchone()
        if existing and existing["state"] == "completed":
            path = archive_path(thread_id, local_date)
            if path.is_file():
                return {"ok": True, "archive_id": existing["archive_id"], "replay": True, "job_key": job_key}
            conn.execute(
                "UPDATE job_runs SET status='retry', lease_token=NULL, lease_until=NULL, updated_at=? WHERE job_key=?",
                (_now(), job_key),
            )
        token = try_lease(conn, job_key)
        if not token:
            return {"ok": False, "error": "lease_busy", "job_key": job_key}
        rows = conn.execute(
            """
            SELECT * FROM chat_messages
            WHERE thread_id=? AND local_date=?
            ORDER BY COALESCE(event_seq, 0), created_at, message_id
            """,
            (thread_id, local_date),
        ).fetchall()
        if not rows:
            conn.execute(
                "UPDATE job_runs SET status='completed', result=?, lease_token=NULL, updated_at=? WHERE job_key=? AND lease_token=?",
                (dumps({"empty": True}), _now(), job_key, token),
            )
            return {"ok": True, "empty": True, "job_key": job_key}
        ids = [r["message_id"] for r in rows]
        seqs = [int(r["event_seq"] or 0) for r in rows]
        snapshot_seq = max(seqs) if seqs else 0
        archive_id = existing["archive_id"] if existing else new_id("arch")
        snap = {"ids": ids, "count": len(ids), "snapshot_seq": snapshot_seq, "archive_id": archive_id}
        conn.execute(
            "UPDATE job_runs SET snapshot=?, updated_at=? WHERE job_key=? AND lease_token=?",
            (dumps(snap), _now(), job_key, token),
        )
        payload = [dict(r) for r in rows]
    text = render_archive_md(thread_id, local_date, archive_id, payload)
    path = archive_path(thread_id, local_date)
    digest = sha256_text(text)
    if path.is_file():
        ok, reason = verify_archive_file(path, digest, len(ids), set(ids))
        if not ok:
            return {"ok": False, "error": "existing_file_conflict", "reason": reason, "job_key": job_key, "kept": str(path)}
    else:
        try:
            written = atomic_write_text(path, text)
            digest = written
        except OSError as exc:
            return {"ok": False, "error": "write_failed", "reason": type(exc).__name__, "job_key": job_key}
    ok, reason = verify_archive_file(path, digest, len(ids), set(ids))
    if not ok:
        return {"ok": False, "error": "verify_failed", "reason": reason, "job_key": job_key}
    from hubv1.store import DATA_DIR, refresh_paths

    refresh_paths()
    try:
        rel = str(path.resolve().relative_to(DATA_DIR.resolve())).replace("\\", "/")
    except Exception:
        rel = f"projections/chat/{thread_id}/{local_date}.md"
    with connect() as conn:
        row = conn.execute("SELECT lease_token, status FROM job_runs WHERE job_key=?", (job_key,)).fetchone()
        if not row or row["lease_token"] != token:
            return {"ok": False, "error": "lease_lost", "job_key": job_key}
        conn.execute(
            """
            INSERT INTO chat_archives(archive_id, thread_id, local_date, snapshot_seq, count, content_hash, path, state, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(thread_id, local_date) DO UPDATE SET
              snapshot_seq=excluded.snapshot_seq, count=excluded.count, content_hash=excluded.content_hash,
              path=excluded.path, state='completed'
            """,
            (archive_id, thread_id, local_date, snapshot_seq, len(ids), digest, rel, "completed", _now()),
        )
        conn.execute(
            "UPDATE chat_messages SET archive_id=? WHERE thread_id=? AND local_date=?",
            (archive_id, thread_id, local_date),
        )
        conn.execute(
            "UPDATE job_runs SET status='completed', result=?, lease_token=NULL, updated_at=? WHERE job_key=? AND lease_token=?",
            (dumps({"archive_id": archive_id, "hash": digest, "count": len(ids)}), _now(), job_key, token),
        )
    return {"ok": True, "archive_id": archive_id, "count": len(ids), "path": rel, "job_key": job_key}


def run_due_jobs() -> dict[str, Any]:
    from hubv1.flags import flag
    from hubv1.publisher import process_queue

    archives = run_chat_archives()
    pub = process_queue() if flag("feature_publisher") else {"skipped": True}
    return {"archives": archives, "publisher": pub}
