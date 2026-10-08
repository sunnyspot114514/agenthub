# Publish request (mock by default)

1. POST `/api/v1/publish/plans` with prefix, `owner/repo`, mode `create|update`, `public`, MIT holder.
2. POST `/api/v1/publish/requests` with `plan_id` and `manifest_hash`.
3. State is `awaiting_approval` / pending. Ordinary agents have no approve route.
4. Live GitHub create/push is a separate owner authorization. Do not claim `verified` without remote hash readback.

This example must not run against a production workspace unless the user explicitly asked and approved the snapshot.
