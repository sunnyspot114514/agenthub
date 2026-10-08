from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Shanghai")
UTC = timezone.utc

_override: Optional[datetime] = None
_clock_error = False


def set_override(dt: Optional[datetime]) -> None:
    global _override
    if dt is None:
        _override = None
        return
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    _override = dt.astimezone(TZ)


def set_clock_error(flag: bool) -> None:
    global _clock_error
    _clock_error = bool(flag)


def snapshot_state() -> tuple[Optional[datetime], bool]:
    return _override, _clock_error


def restore_state(override: Optional[datetime], err: bool) -> None:
    global _override, _clock_error
    _override = override
    _clock_error = err


def clock_error() -> bool:
    return _clock_error


def now() -> datetime:
    if _clock_error:
        raise RuntimeError("clock_error")
    if _override is not None:
        return _override
    return datetime.now(TZ)


def now_utc() -> datetime:
    return now().astimezone(UTC)


def now_iso() -> str:
    return now_utc().isoformat()


def shanghai_date(dt: Optional[datetime] = None) -> str:
    return (dt or now()).astimezone(TZ).date().isoformat()


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def slot_id(work_date: str, hour: int) -> str:
    return f"{work_date}@{hour:02d}:00+08:00"


def slot_cutoff(work_date: str, hour: int) -> datetime:
    y, m, d = (int(x) for x in work_date.split("-"))
    return datetime(y, m, d, hour, 0, 0, tzinfo=TZ)


def due_slots(at: Optional[datetime] = None) -> list[tuple[str, int]]:
    """Slots whose cutoff has already passed (today and yesterday). Future slots are omitted."""
    at = (at or now()).astimezone(TZ)
    out: list[tuple[str, int]] = []
    for back in (1, 0):
        day = (at.date() - timedelta(days=back)).isoformat()
        for hour in (8, 20):
            if at >= slot_cutoff(day, hour):
                out.append((day, hour))
    return out


def window_for(hour: int, work_date: str) -> tuple[datetime, datetime]:
    if hour == 8:
        start = slot_cutoff(work_date, 0)
        end = slot_cutoff(work_date, 8)
    elif hour == 20:
        start = slot_cutoff(work_date, 8)
        end = slot_cutoff(work_date, 20)
    else:
        raise ValueError("hour")
    return start, end


def shanghai_day_bounds(day: str) -> tuple[str, str]:
    start = slot_cutoff(day, 0).astimezone(UTC)
    end = start + timedelta(days=1)
    return start.isoformat(), end.isoformat()


def parse_test_clock(value: str) -> datetime:
    return parse_iso(value).astimezone(TZ)


def add(dt: datetime, **kwargs) -> datetime:
    return dt + timedelta(**kwargs)
