"""Typed shapes used by the CLI. Keep in sync with docs/api-contract.md."""
from __future__ import annotations

from typing import Any, TypedDict


class ErrorBody(TypedDict, total=False):
    code: str
    message: str
    retryable: bool
    details: dict[str, Any]


class Envelope(TypedDict, total=False):
    schema_version: str
    request_id: str
    data: Any
    error: ErrorBody
