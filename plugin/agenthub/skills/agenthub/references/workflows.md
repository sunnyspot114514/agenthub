# Workflows

## OAuth

Use the host OAuth connection. Access tokens are short. Refresh is handled by the host. If the connection fails, ask the user to reconnect in Agenthub; do not paste tokens.

## Text write

`workspace_write_text` with relative_path, UTF-8 text, expected_revision on overwrite, idempotency_key on retries.

## Binary

1. `binary_begin` with filename, byte size, optional SHA-256. The result is a PUT URL plus a short-lived one-use ticket.
2. The host runtime PUTs raw bytes to `put_url` using the short-lived ticket from `binary_begin`, or the same OAuth access token. Do not Base64. Do not open ChatGPT/host filesystem paths. Do not fetch Library IDs or arbitrary URLs.
3. `binary_status` until `state` is `ready`.
4. `import_prepare` with `staging_id`, then `import_commit` with `preview_id` + `manifest_hash`.
5. Never paste `upload_ticket` into chat or workspace files.

## Publish

`publish_prepare` then `publish_request`. Status via `publish_status`. Owner approves on the Agenthub website.
