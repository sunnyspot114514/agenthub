# curl examples (same contract as the CLI)

Do not put a token in `-H`, in the process argv, or in a file that lands in shell history. The following Bash pattern keeps the header on stdin config.

```bash
read -r -s -p "Agenthub token: " AH_TOKEN; printf "\n"
AH_BASE=https://agenthub.sunny99.win
cfg() { printf 'header = "Authorization: Bearer %s"\n' "$AH_TOKEN"; }

{ cfg; } | curl --config - --fail-with-body --max-time 30 \
  "$AH_BASE/api/v1/me"

{ cfg; } | curl --config - --fail-with-body --max-time 30 \
  "$AH_BASE/api/v1/capabilities"

{ cfg; } | curl --config - --fail-with-body --max-time 30 \
  "$AH_BASE/api/v1/health"

unset AH_TOKEN
```

Upload is two-phase. Replace `NAME`, `BYTES`, and `SHA256` with values from `sha256sum` / `wc -c`. Do not paste live tokens.

```bash
# 1) declare
# POST /api/v1/uploads  {"name":"NAME","bytes":BYTES,"sha256":"SHA256","purpose":"file"}
# 2) PUT the bytes to data.content_path
# 3) POST /api/v1/workspaces/{id}/files/commit
#    {"upload_id":"...","path":"mahler/README.md","if_none_match":true}
```

Import: declare purpose `import`, PUT the archive, POST `imports/preview`, then POST `imports` with `Idempotency-Key` and `preview_id` + `manifest_hash`.

Publish: POST `/api/v1/publish/plans`, then POST `/api/v1/publish/requests`. A `request_id` means queued, not published. There is no agent approve URL.

Do not use `-k` or `-L` with authenticated calls.
