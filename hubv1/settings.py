"""Runtime config from environment / .env. Defaults match the existing deploy."""
from __future__ import annotations

import os
from datetime import datetime
from zoneinfo import ZoneInfo

DEFAULT_PUBLIC_HOST = "agenthub.sunny99.win"
DEFAULT_GIT_AUTHOR_NAME = "sunnyspot114514"
DEFAULT_GIT_AUTHOR_EMAIL = "104133192+sunnyspot114514@users.noreply.github.com"
DEFAULT_COPYRIGHT_HOLDER = "sunnyspot114514"
DEFAULT_TZ = "Asia/Shanghai"


def _clean(value: str | None, fallback: str) -> str:
    text = (value or "").strip()
    return text or fallback


def public_host() -> str:
    return _clean(os.getenv("AGENTHUB_PUBLIC_HOST"), DEFAULT_PUBLIC_HOST)


def public_origin() -> str:
    return f"https://{public_host()}"


def git_author_name() -> str:
    return _clean(os.getenv("AGENTHUB_GIT_AUTHOR_NAME"), DEFAULT_GIT_AUTHOR_NAME)


def git_author_email() -> str:
    return _clean(os.getenv("AGENTHUB_GIT_AUTHOR_EMAIL"), DEFAULT_GIT_AUTHOR_EMAIL)


def copyright_holder_default() -> str:
    return _clean(os.getenv("AGENTHUB_COPYRIGHT_HOLDER"), DEFAULT_COPYRIGHT_HOLDER)


def timezone_name() -> str:
    name = _clean(os.getenv("AGENTHUB_TZ"), DEFAULT_TZ)
    try:
        ZoneInfo(name)
        return name
    except Exception:
        return DEFAULT_TZ


def tz() -> ZoneInfo:
    return ZoneInfo(timezone_name())


def license_year(at: datetime | None = None) -> str:
    when = at or datetime.now(tz())
    return str(when.astimezone(tz()).year)


def trusted_proxies() -> set[str]:
    raw = os.getenv("AGENTHUB_TRUSTED_PROXIES", "127.0.0.1,::1")
    return {part.strip() for part in raw.split(",") if part.strip()}
