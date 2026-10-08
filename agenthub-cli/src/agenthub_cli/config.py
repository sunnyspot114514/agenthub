from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


def config_path() -> Path:
    return Path.home() / ".config" / "agenthub" / "config.json"


def load() -> dict:
    p = config_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save(data: dict) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    clean = {k: v for k, v in data.items() if k not in {"token", "authorization"}}
    p.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    try:
        p.chmod(0o600)
    except Exception:
        pass


def set_base_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("base-url must be https (localhost http allowed for tests)")
    cfg = load()
    cfg["base_url"] = url.rstrip("/")
    save(cfg)
