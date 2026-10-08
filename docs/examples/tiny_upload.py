#!/usr/bin/env python3
"""Tiny own-file upload via two-phase API. Stdlib only. Fixture text, not production files."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("AGENTHUB_BASE", "https://agenthub.sunny99.win").rstrip("/")
TOKEN = os.environ.get("AGENTHUB_TOKEN") or ""
PAYLOAD = b"agenthub-v15-fixture\n"


def req(method: str, path: str, *, data: bytes | None = None, json_body=None, content_type: str | None = None):
    headers = {"Authorization": "Bearer " + TOKEN, "Accept": "application/json"}
    body = data
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif content_type:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body or b""))
    r = urllib.request.Request(BASE + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            raw = resp.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            return resp.status, parsed, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            parsed = {"error": {"code": "http", "message": raw[:200].decode("utf-8", "replace")}}
        return exc.code, parsed, raw


def main() -> int:
    if not TOKEN:
        print("need AGENTHUB_TOKEN")
        return 3
    code, me, _ = req("GET", "/api/v1/me")
    if code != 200:
        print("me", code, (me.get("error") or {}).get("code"))
        return 3 if code == 401 else 4
    wid = (me.get("data") or {}).get("own_workspace_id") or (me.get("data") or {}).get("workspace_id")
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    code, decl, _ = req(
        "POST",
        "/api/v1/uploads",
        json_body={"name": "v15-fixture.txt", "bytes": len(PAYLOAD), "sha256": digest, "purpose": "file"},
    )
    if code not in (200, 201):
        print("declare", code)
        return 7
    uid = (decl.get("data") or {}).get("upload_id")
    path = (decl.get("data") or {}).get("content_path") or f"/api/v1/uploads/{uid}/content"
    code, _put, _ = req("PUT", path, data=PAYLOAD, content_type="application/octet-stream")
    if code != 200:
        print("put", code)
        return 7
    code, committed, _ = req(
        "POST",
        f"/api/v1/workspaces/{wid}/files/commit",
        json_body={"upload_id": uid, "path": "v15/fixture.txt", "if_none_match": True},
    )
    print("commit", code, (committed.get("data") or {}).get("path"))
    return 0 if code in (200, 201) else 6


if __name__ == "__main__":
    raise SystemExit(main())
