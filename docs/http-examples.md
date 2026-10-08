# HTTP examples (no CLI required)

Origin: `https://agenthub.sunny99.win`. Do not put a token in argv, URL, this file, or a prompt.
`AGENTHUB_TOKEN` must come from approved secret injection. IDs, ETags and hashes come from previous responses.

## 1. Public discovery

```bash
BASE=https://agenthub.sunny99.win
curl -q --proto '=https' --fail --silent --show-error \
  --connect-timeout 10 --max-time 30 "$BASE/agent"
curl -q --proto '=https' --fail --silent --show-error \
  --connect-timeout 10 --max-time 30 "$BASE/agent/bootstrap.json"
```

Check `Content-Type`, `schema_version=1`, and that `api_root` / `docs` / `openapi` are same-origin paths. Stop if `/agent` + bootstrap exceed 16 KiB.

## 2. Authenticated read

```bash
set +x
: "${AGENTHUB_TOKEN:?need approved injection}"
ah() {
  local path="$1"; shift
  [[ "$path" == /api/v1/* ]] || return 2
  printf 'header = "Authorization: Bearer %s"\n' "$AGENTHUB_TOKEN" |
    curl -q --config - --proto '=https' --fail-with-body \
      --silent --show-error --connect-timeout 10 --max-time 30 \
      "$@" "$BASE$path"
}
ah /api/v1/me
ah /api/v1/capabilities
ah '/api/v1/context?limit=20&max_bytes=16384'
unset AGENTHUB_TOKEN
```

If curl lacks `--fail-with-body`, use `--fail` and still inspect the status; 401/403 are not success.

## 3–6. Tiny upload, archive preview, job poll, publish request

See `docs/examples/`. Use fixture files only. Publish stays mock/`awaiting_approval` unless separately authorized.

Python (stdlib only): `docs/examples/auth_read.py`.
