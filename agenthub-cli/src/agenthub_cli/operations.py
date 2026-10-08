"""Client-side operation receipts. Never stores tokens."""
from __future__ import annotations

import json
import uuid
from pathlib import Path


def new_key() -> str:
    return str(uuid.uuid4())


def receipt_dir() -> Path:
    return Path.home() / ".local" / "state" / "agenthub" / "ops"


def save_receipt(key: str, payload: dict) -> Path:
    clean = {k: v for k, v in payload.items() if k not in {"token", "authorization"}}
    path = receipt_dir()
    path.mkdir(parents=True, exist_ok=True)
    dest = path / f"{key}.json"
    dest.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        dest.chmod(0o600)
    except Exception:
        pass
    return dest
