from __future__ import annotations

import json
import sys
from typing import Any


def emit(data: Any, *, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2 if not isinstance(data, dict) else None))
        if not str(json.dumps(data)).endswith("\n"):
            sys.stdout.write("\n")
        return
    if isinstance(data, dict):
        for k, v in data.items():
            if k in {"token", "authorization", "sha256_secret"}:
                continue
            sys.stdout.write(f"{k}: {v}\n")
        return
    sys.stdout.write(str(data) + "\n")


def emit_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, ensure_ascii=False) + "\n")


def warn(msg: str) -> None:
    sys.stderr.write(msg.rstrip() + "\n")
