"""Public URL-first discovery. No user data, tokens, or internal topology."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from hubv1.version import APP_VERSION as API_VERSION
BOOTSTRAP_SCHEMA = 1
AGENT_MAX = 12 * 1024
BOOTSTRAP_MAX = 4 * 1024
DISCOVERY_BUDGET = 16 * 1024

BOOTSTRAP: dict[str, Any] = {
    "schema_version": BOOTSTRAP_SCHEMA,
    "service": "agenthub",
    "api_version": API_VERSION,
    "api_root": "/api/v1",
    "auth": {"scheme": "bearer", "obtain": "owner-provisioned", "mcp": "oauth2-pkce"},
    "docs": "/agent",
    "openapi": "/openapi.json",
    "capabilities": "/api/v1/capabilities",
    "clients": ["https-json", "curl", "python"],
    "cli": {"required": False, "releases": None},
}

REQUIRED_BOOTSTRAP = (
    "schema_version",
    "service",
    "api_version",
    "api_root",
    "auth",
    "docs",
    "openapi",
    "capabilities",
    "clients",
    "cli",
)

PUBLIC_OPENAPI_SKIP_PREFIXES = ("/console", "/mcp")
PUBLIC_OPENAPI_SKIP_EXACT = {"/session", "/session/logout"}

DISCOVERY_LINK = (
    '</agent>; rel="service-doc", '
    '</agent/bootstrap.json>; rel="describedby", '
    '</openapi.json>; rel="describedby"'
)


def bootstrap() -> dict[str, Any]:
    return {
        "schema_version": int(BOOTSTRAP["schema_version"]),
        "service": str(BOOTSTRAP["service"]),
        "api_version": str(BOOTSTRAP["api_version"]),
        "api_root": str(BOOTSTRAP["api_root"]),
        "auth": dict(BOOTSTRAP["auth"]),
        "docs": str(BOOTSTRAP["docs"]),
        "openapi": str(BOOTSTRAP["openapi"]),
        "capabilities": str(BOOTSTRAP["capabilities"]),
        "clients": list(BOOTSTRAP["clients"]),
        "cli": dict(BOOTSTRAP["cli"]),
    }


def validate_bootstrap(doc: dict[str, Any], *, origin: str = "") -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_BOOTSTRAP:
        if key not in doc:
            errors.append(f"missing {key}")
    if doc.get("schema_version") != 1:
        errors.append("schema_version")
    if doc.get("service") != "agenthub":
        errors.append("service")
    auth = doc.get("auth") or {}
    if auth.get("scheme") != "bearer" or auth.get("obtain") != "owner-provisioned":
        errors.append("auth")
    if doc.get("cli", {}).get("required") is not False:
        errors.append("cli.required")
    for key in ("api_root", "docs", "openapi", "capabilities"):
        val = str(doc.get(key) or "")
        if not val.startswith("/") or val.startswith("//") or "://" in val:
            errors.append(f"absolute-or-bad {key}")
    dumped = str(doc).lower()
    for bad in ("token", "authorization", "127.0.0.1", "192.168.", "ghp_", "gho_"):
        if bad in dumped:
            errors.append(f"leaked {bad}")
    if origin:
        parsed = urlparse(origin)
        if parsed.scheme and parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
            errors.append("origin must be https")
    return errors


def same_origin_api(pointer: str, origin: str) -> bool:
    if not pointer:
        return False
    if pointer.startswith("/"):
        return not pointer.startswith("//")
    parsed = urlparse(pointer)
    base = urlparse(origin)
    if parsed.scheme and parsed.scheme != "https":
        return False
    return parsed.netloc == base.netloc


def agent_markdown() -> str:
    b = bootstrap()
    return f"""# Agenthub agent access

This page is for agents that already have an owner-provisioned Bearer token. It is a protocol card so those agents can call HTTPS (curl or Python) without installing a CLI or opening the graphical console. Opening this URL does not log you in, does not grant a token, and does not start background tasks.

Anonymous visitors only see this note plus `/about`. They cannot read chat, logs, workspaces, or library files.

## Public vs authenticated

Public (no cookie, no JS, no token): `/agent`, `/agent/bootstrap.json`, `/openapi.json`, `/about` (approved bio only), `/health`.

If you already hold a token: GET `/api/v1/me`, `/api/v1/capabilities`, `/api/v1/context`, then workspace files, import jobs, and publish requests as your scopes allow.

## Token

Use the token the owner already gave you, via the host's approved secret injection. This site does not mint, email, or enlarge tokens. Do not put a token in a URL, argv, this page, or a prompt. After use, unset it.

Auth scheme: `{b["auth"]["scheme"]}` (`{b["auth"]["obtain"]}`).

## First reads

1. GET `{b["docs"]}` and `{b["openapi"]}` (this page and schema).
2. With a token, GET `/api/v1/me` then `{b["capabilities"]}`.
3. GET `/api/v1/context?limit=20&max_bytes=16384` for a short own-workspace index. Stop if truncated.
4. Write only with matching scope, ownership, and an explicit user task. Publish stays pending until a human approves.

## Writes (already implemented; still authorization-gated)

Two-phase upload, atomic ZIP/TAR/TAR.GZ import, idempotent jobs, human-approved GitHub publish. No second upload stack. MCP supports OAuth plus restricted write tools (own-workspace text, approved chat, publish request, ticketed binary PUT then import). Host streams raw bytes to the signed PUT URL; do not Base64 ZIPs, open host filesystem paths, or fetch arbitrary URLs. Agents do not get Pi shell, system config, or publisher credentials.

## Failures

401 JSON: missing/invalid/revoked token. 403: scope or owner. 409/412: conflict. 413: too large. 422: archive/input. 429: rate limit. Do not treat HTML login as an API success. Do not follow cross-origin redirects with Authorization.

## Optional CLI

CLI is not required. `cli.required` is false; `cli.releases` is null until a separately authorized immutable release exists. Do not `curl | sh`. Do not auto-install.

## Pointers

- bootstrap: `/agent/bootstrap.json` (schema_version={b["schema_version"]}, api_version={b["api_version"]}, api_root={b["api_root"]})
- OpenAPI: `{b["openapi"]}`
- clients: {", ".join(b["clients"])}

Keep `/agent` + bootstrap under 16 KiB combined. Do not dump OpenAPI or library archives into context by default.
"""


def llms_txt() -> str:
    return """# Agenthub
> Home Agent Hub. Not an LLM. This file is a local pointer set, not a general standard.

- Agent access: /agent
- Bootstrap: /agent/bootstrap.json
- OpenAPI: /openapi.json
- OAuth AS: /.well-known/oauth-authorization-server
- MCP resource: /.well-known/oauth-protected-resource/mcp
- About (approved public bio only): /about
"""


def sanitize_openapi(schema: dict[str, Any], *, public_origin: str) -> dict[str, Any]:
    paths = schema.get("paths") or {}
    kept = {}
    for path, methods in paths.items():
        if path in PUBLIC_OPENAPI_SKIP_EXACT:
            continue
        if any(path.startswith(p) for p in PUBLIC_OPENAPI_SKIP_PREFIXES):
            continue
        cleaned = {}
        for method, op in (methods or {}).items():
            if not isinstance(op, dict):
                cleaned[method] = op
                continue
            item = dict(op)
            item.pop("example", None)
            if isinstance(item.get("requestBody"), dict):
                item["requestBody"] = {k: v for k, v in item["requestBody"].items() if k != "example"}
            cleaned[method] = item
        kept[path] = cleaned
    schema["paths"] = kept
    schema["servers"] = [{"url": public_origin, "description": "confirmed HTTPS origin"}]
    info = dict(schema.get("info") or {})
    info["description"] = (
        "Agenthub REST. Public GETs have security []. Private operations require Bearer. "
        "OpenAPI lists protocol operations; GET /api/v1/capabilities lists this identity's current rights."
    )
    schema["info"] = info
    return schema
