#!/usr/bin/env python3
"""Authenticated read with stdlib urllib. Token from AGENTHUB_TOKEN only."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("AGENTHUB_BASE", "https://agenthub.sunny99.win").rstrip("/")
TOKEN = os.environ.get("AGENTHUB_TOKEN") or os.environ.get("AH_TOKEN")


def get(path: str, token: str | None = None) -> tuple[int, dict | str]:
    if not path.startswith("/"):
        raise SystemExit("path must be origin-relative")
    req = urllib.request.Request(BASE + path, method="GET")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype:
                return resp.status, json.loads(raw.decode("utf-8"))
            return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"error": {"message": body[:200], "code": "http"}}
        return exc.code, parsed


def main() -> int:
    status, agent = get("/agent")
    print("agent_status", status, "bytes", len(str(agent)))
    status, boot = get("/agent/bootstrap.json")
    if status != 200 or not isinstance(boot, dict) or boot.get("schema_version") != 1:
        print("bootstrap_failed", status)
        return 8
    if not TOKEN:
        print("no_token_stop_after_public")
        return 0
    for path in ("/api/v1/me", "/api/v1/capabilities", "/api/v1/context?limit=20&max_bytes=16384"):
        code, body = get(path, TOKEN)
        err = (body or {}).get("error") if isinstance(body, dict) else None
        ident = ""
        if isinstance(body, dict):
            ident = str((body.get("data") or {}).get("identity_id") or (body.get("data") or {}).get("identity") or "")
        print(path, code, ident, (err or {}).get("code") if err else "ok")
        if code == 401:
            return 3
        if code == 403:
            return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
