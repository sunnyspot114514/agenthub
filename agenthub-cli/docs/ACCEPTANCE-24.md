# Acceptance 01–24 — CLI 0.1.0 / API 1.3.0

Host: Windows 10 amd64. Date: 2026-10-07. GitHub publish: **mock only** (no live repo create). Pi not deployed (spec: this document is not install/config/credential/GitHub-publish authorization).

Artifacts:

- `dist/agenthub_cli-0.1.0-py3-none-any.whl`
- `dist/agenthub_cli-0.1.0.tar.gz`
- `dist/SHA256SUMS`

Tests: `python test_v14.py` 24/24 OK; `test_v10.py` 27/27; `test_v12.py` 8/8; `test_publish.py` 3/3; CLI parser contract 3/3.

| # | Scene | Result |
| --- | --- | --- |
| 01 | Blank venv install wheel; `agenthub --help` and `python -m agenthub_cli --help`; no extra service | PASS (Windows isolated venv) |
| 02 | Old client / missing capability → exit 10, no guessed endpoints | PASS (`chat` stub 10; `min_client_version` 0.1.0) |
| 03 | 401 / bad token; no credential in output | PASS |
| 04 | agent writes only own workspace; approve 403 | PASS |
| 05 | No `--token` / `--insecure`; health has no token; CLI blocks cross-origin auth redirects | PASS (client `follow_redirects=False`) |
| 06 | files cursor/limit/max_bytes; context not a full dump | PASS |
| 07 | Stream upload hash; invisible until commit | PASS |
| 08 | Declared vs actual bytes/hash fail and purge | PASS |
| 09 | Over upload cap 413/422 distinct from workspace quota | PASS (upload cap) |
| 10 | Same Idempotency-Key found via `/operations/{key}` | PASS |
| 11 | Same key same body reuse; same key different body 409 | PASS |
| 12 | Stale ETag 412; original bytes unchanged | PASS |
| 13 | ZIP/TAR.GZ keep paths; Mac metadata skipped | PASS |
| 14 | 7z stored as file; nested ZIP not expanded | PASS |
| 15 | Absolute / `..` paths rejected | PASS |
| 16 | Symlink TAR and casefold duplicate ZIP rejected | PASS |
| 17 | import_members limit stops preview | PASS |
| 18 | Encrypted ZIP, `.git`, `.exe` rejected | PASS |
| 19 | Job queryable after success; missing job 404 | PASS (in-process; live Pi restart not run) |
| 20 | Download by path; traversal rejected; no remote delete | PASS |
| 21 | Publish request queued `awaiting_approval`; no GitHub URL; agent cannot approve | PASS (mock) |
| 22 | Wrong manifest_hash 412; snapshot not rewritten by later files | PASS (mock) |
| 23 | `publish_approve` false; no force-push in client | PASS (mock; live verified GitHub **not** claimed) |
| 24 | JSON stdout; Windows run; ARM64/macOS not executed this session | PASS on Windows; ARM64/macOS pending runtime check |

## Known limits

- Import jobs run inline then persist `succeeded`/`failed` (still HTTP 202).
- Resumable/chunked upload is off.
- Chat/logs/brief/context CLI commands exit 10.
- Cloudflare public body limit and GitHub file size are not the same as workspace 50 GiB quota.
- Independent backup remains off.
- No Pi deploy, no new tokens, no real GitHub repository from this change set.
