# Observed API vs v1.4 proposed contract

Inventory date: 2026-10-07. Source tree `agenthub-src` (not a live Pi deploy). `/api/shared` remains an alias onto the same handlers.

## Observed (already present before this version)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/health` | App-level liveness, not versioned |
| GET | `/api/v1/context` | Existing shared context; not the CLI `context` command |
| GET | `/api/v1/capabilities` | Workspace flags; now includes `api_version` 1.3.0 and CLI fields |
| GET | `/api/v1/workspaces`, `/workspaces/me` | Owner workspace |
| GET/POST | `/api/v1/workspaces/me/nodes`, `/uploads` | Node CRUD and multipart ingest |
| GET | `/api/v1/nodes/{id}/file` | Stream by node id |
| GET/POST | `/api/v1/publish-requests` | Request + admin approve/reject |
| GET | `/api/v1/jobs` | Embedded scheduler job_runs, not xfer jobs |

## Added in 1.3.0 / CLI 0.1.0 (needs-change → implemented)

| Method | Path | Mapping |
| --- | --- | --- |
| GET | `/api/v1/health` | `{ok, ready}`; no topology |
| GET | `/api/v1/me` | identity, workspace_id, scopes, disabled |
| POST | `/api/v1/uploads` | declare name/bytes/sha256/purpose |
| PUT | `/api/v1/uploads/{id}/content` | stream bytes; hash/size check |
| POST | `/api/v1/workspaces/{id}/files/commit` | atomic visible write |
| GET | `/api/v1/workspaces/{id}/files` | cursor/limit/max_bytes |
| GET | `/api/v1/workspaces/{id}/files/content` | `?path=` stream |
| POST | `/api/v1/workspaces/{id}/imports/preview` | freeze manifest, no write |
| POST | `/api/v1/workspaces/{id}/imports` | 202 + Idempotency-Key |
| GET | `/api/v1/jobs/{id}` | xfer job (distinct from GET `/jobs`) |
| GET | `/api/v1/operations/{key}` | idempotent write lookup |
| POST | `/api/v1/publish/plans` | freeze file list; no GitHub write |
| POST | `/api/v1/publish/requests` | plan_id + manifest_hash → pending approval |
| GET | `/api/v1/publish/requests/{id}` | alias of publish-requests get |

## Explicitly not added

- Pi shell / SSH / remote exec
- Agent self-approve
- Resumable chunked upload (`features.resumable_upload=false`)
- Bidirectional workspace sync / remote delete
- Chat, logs, brief CLI (exit 10 until a later version)
