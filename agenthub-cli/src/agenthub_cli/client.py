from __future__ import annotations

import hashlib
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from agenthub_cli.errors import CliError, map_http


class HubClient:
    def __init__(self, base_url: str, token: Optional[str], *, timeout: float = 30.0):
        if not base_url:
            raise CliError("base-url not set", 2)
        self.base = base_url.rstrip("/")
        self.token = token
        self._client = httpx.Client(base_url=self.base, timeout=httpx.Timeout(timeout, connect=10.0), follow_redirects=False, verify=True)

    def close(self) -> None:
        self._client.close()

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = self._headers()
        extra = kwargs.pop("headers", {}) or {}
        headers.update(extra)
        url = path if path.startswith("http") else urljoin(self.base + "/", path.lstrip("/"))
        parsed = urlparse(url)
        base_host = urlparse(self.base)
        if parsed.netloc and parsed.netloc != base_host.netloc:
            raise CliError("refusing cross-origin request", 5)
        resp = self._client.request(method, url, headers=headers, **kwargs)
        if resp.is_redirect:
            loc = resp.headers.get("location") or ""
            loc_host = urlparse(urljoin(url, loc)).netloc
            if loc_host and loc_host != base_host.netloc:
                raise CliError("cross-origin redirect blocked", 5)
        return resp

    def json(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        resp = self.request(method, path, **kwargs)
        try:
            body = resp.json()
        except Exception:
            body = {"error": {"message": resp.text[:200], "code": "http"}}
        if resp.status_code >= 400:
            raise CliError((body.get("error") or {}).get("message") or resp.reason_phrase, map_http(resp.status_code, body), body)
        return body if isinstance(body, dict) else {"data": body}

    def put_bytes(self, path: str, data: bytes, *, content_type: str = "application/octet-stream") -> dict[str, Any]:
        return self.json("PUT", path, content=data, headers={"Content-Type": content_type, "Content-Length": str(len(data))})


def sha256_file(path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return size, h.hexdigest()
