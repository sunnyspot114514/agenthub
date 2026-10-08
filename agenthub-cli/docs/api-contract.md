# CLI ↔ API contract (v0.1.0 client / 1.3.0 API)

`--json` stdout is one UTF-8 JSON object. Progress and diagnostics go to stderr.

## Success envelope

```json
{"schema_version":"1.3.0","request_id":"<id>","data":{},"cursor":null,"stale":false,"omitted":0}
```

Lists under `data` also carry `next_cursor`, `truncated`, `returned_bytes`.

## Error envelope

```json
{"error":{"code":"<code>","message":"<short>","retryable":false,"details":{}},"request_id":"<id>"}
```

Client maps status, not message text: 401→3, 403→4, 404→5, 409/412→6, 413/422→7, network/unknown write→8, job failed→9, incompatible→10, wait budget→11.

## Capabilities (structure)

`api_version`, `min_client_version`, `identity`, `workspace_id`, `scopes`, `limits`, `archives`, `features`, `idempotency_ttl_seconds`. Feature booleans are true only after the matching handler exists.

## Auth

Bearer token from `AGENTHUB_TOKEN` or `AH_TOKEN`. Optional keyring after `auth login --store keyring`. Tokens never appear in argv, URLs, config.json, or logs.
