# Observed API vs v1.5 URL-first plan

Inventory date: 2026-10-08. Source tree only. **deployed: no.**

Legend: existing = already in tree before this increment; reused = kept and mapped; added = this increment.

## Public discovery

| Method | Path | Status | Auth |
| --- | --- | --- | --- |
| GET | `/` | existing + homepage link to `/agent` | none |
| GET | `/health` | existing | none |
| GET | `/about` | existing approved bio | none |
| GET | `/.well-known/agenthub.json` | existing; now points at `/agent` | none |
| GET | `/openapi.json` | existing; now sanitized (no `/console`, no `/mcp`, no cookie session) | none |
| GET | `/agent` | **added** text/markdown ≤12 KiB | none |
| GET | `/agent/bootstrap.json` | **added** schema_version=1 ≤4 KiB | none |
| GET | `/llms.txt` | **added** optional pointer | none |

## Authenticated read (reused, fields extended)

| Method | Path | Status |
| --- | --- | --- |
| GET | `/api/v1/me` | reused; `identity_id`, `own_workspace_id` aliases |
| GET | `/api/v1/capabilities` | reused; v1.5 feature/limit/link fields; unknown proxy limit `null` |
| GET | `/api/v1/context` | reused; `limit`/`max_bytes`/`cursor`; own workspace file index first |
| GET | `/api/v1/health` | existing from v1.4 |

## Writes (v1.4 reused, not rewritten)

Two-phase upload, import preview/job, publish plans/requests, ownership, human approve. See `agenthub-cli/docs/observed-api.md`.

## Errors

`/api/*` 401/403 now include `{error.code,message,retryable,request_id}` plus legacy `detail`. Private `Cache-Control: no-store`.

## Rollback

Remove `/agent`, `/agent/bootstrap.json`, `/llms.txt`, homepage Agent link, OpenAPI filter, discovery Link header. Restore previous `me`/`capabilities`/`context` field set if a client forbids additive keys. Do not delete blobs or loosen ACL.

## Status tags

- public_discovery: implemented + tested locally; **not deployed**
- authenticated_read: implemented + tested locally; **not deployed**
- upload_pass: covered by v1.4/v1.5 tests locally
- remote_publish_verified: **no** (mock only)
