from __future__ import annotations

import os
from typing import Optional

from agenthub_cli import config as cfgmod


def token_from_env() -> Optional[str]:
    return os.environ.get("AGENTHUB_TOKEN") or os.environ.get("AH_TOKEN")


def load_token(*, allow_store: bool = False) -> Optional[str]:
    env = token_from_env()
    if env:
        return env.strip() or None
    if not allow_store:
        return None
    try:
        import keyring
    except Exception:
        return None
    saved = keyring.get_password("agenthub", cfgmod.load().get("profile") or "default")
    return saved.strip() if saved else None


def store_token(token: str) -> str:
    try:
        import keyring
    except Exception:
        return "env"
    keyring.set_password("agenthub", cfgmod.load().get("profile") or "default", token)
    return "keyring"


def clear_local() -> None:
    try:
        import keyring

        keyring.delete_password("agenthub", cfgmod.load().get("profile") or "default")
    except Exception:
        pass
