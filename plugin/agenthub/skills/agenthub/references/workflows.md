# Workflows

## OAuth

Use the host OAuth connection. Access tokens are short. Refresh is handled by the host. If the connection fails, ask the user to reconnect in Agenthub; do not paste tokens.

## Text write

`workspace_write_text` with relative_path, UTF-8 text, expected_revision on overwrite, idempotency_key on retries.

## Binary

1. `workspace_stage_file` with the user ZIP in the `file` parameter (host file picker / `openai/fileParams`). Returns `staging_id` already `ready`.
2. If the host cannot attach a file, call `workspace_stage_file` / `binary_begin` with `name` and `declared_bytes` to get a one-time PUT URL, then PUT raw bytes, then `binary_status` until `ready`.
3. `import_prepare` with `staging_id`, then `import_commit` with `preview_id` + `manifest_hash`.
4. Models must not invent Base64 of large ZIPs. Do not open host filesystem paths or fetch Library IDs. Do not paste upload tickets into chat.

## Text write errors

- Stale `expected_revision` → `REVISION_CONFLICT` plus `current_revision`.
- Same `idempotency_key` with a different body → `IDEMPOTENCY_CONFLICT`.
- `workspace_read` with a missing revision → `REVISION_NOT_FOUND`, never silent HEAD.

## Publish

`publish_prepare` then `publish_request`. Status via `publish_status`. Owner approves on the Agenthub website.
