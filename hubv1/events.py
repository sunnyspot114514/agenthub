from __future__ import annotations

import json
from typing import Any, Optional

from hubv1.store import dumps, new_id
from hubv1.timeutil import now_iso


def append_event(
    conn,
    typ: str,
    actor_id: str,
    payload: dict[str, Any],
    *,
    project_id: Optional[str] = None,
) -> int:
    eid = new_id("evt")
    cur = conn.execute(
        """
        INSERT INTO hub_events(event_id, type, actor_id, project_id, created_at_utc, payload, schema_version)
        VALUES (?,?,?,?,?,?,12)
        """,
        (eid, typ, actor_id, project_id, now_iso(), dumps(payload)),
    )
    seq = cur.lastrowid
    if not seq:
        row = conn.execute("SELECT seq FROM hub_events WHERE event_id=?", (eid,)).fetchone()
        seq = int(row["seq"]) if row else 0
    return int(seq)


def current_seq(conn) -> int:
    row = conn.execute("SELECT COALESCE(MAX(seq),0) AS n FROM hub_events").fetchone()
    return int(row["n"] if row else 0)


def load_payload(raw: str) -> dict[str, Any]:
    try:
        val = json.loads(raw or "{}")
        return val if isinstance(val, dict) else {}
    except Exception:
        return {"_parse_error": True}
