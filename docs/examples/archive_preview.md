# Archive preview then commit (fixture only)

After authenticated read, reuse v1.4 two-phase upload with `purpose: import`.

1. POST `/api/v1/uploads` with archive `name`, `bytes`, `sha256`, `purpose=import`.
2. PUT bytes to `data.content_path`.
3. POST `/api/v1/workspaces/{own_workspace_id}/imports/preview` `{"upload_id","dest"}`.
4. Inspect members, skipped, rejected, `manifest_hash`. Nested ZIP/TAR stay ordinary files.
5. POST `/api/v1/workspaces/{id}/imports` with `Idempotency-Key`, `preview_id`, `manifest_hash`, `conflict=fail`.
6. Expect 202. Then GET `/api/v1/jobs/{job_id}` until `succeeded` or `failed`. Do not treat 202 as unpacked.
