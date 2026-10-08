# Acceptance 01–15 — URL-first v1.5 / API 1.3.1

Date: 2026-10-08. Host: Windows. **deployed: no.** GitHub: mock only.

`python test_v15.py` 15/15 OK locally.

| # | Result | Notes |
| --- | --- | --- |
| 01 | tested | `/agent` markdown, bootstrap schema_version=1, homepage 入口, no login |
| 02 | tested local; live 403 | Cloudflare/origin on `/agent` blocked; not bypassed; **not deployed** |
| 03 | tested | no tokens, identities, 192.168, console paths in public trio |
| 04 | tested | OpenAPI from routes; `/console` `/mcp` stripped; bearer vs security [] |
| 05 | tested | 401 JSON `error.code=unauthorized`; no-store; no login HTML |
| 06 | tested | read-only cannot write; own commit 201; cross-owner 403; no approve |
| 07 | tested | remaining bytes int; proxy limit null; unimplemented resumable false |
| 08 | tested | cross-origin API pointer and HTTP downgrade rejected |
| 09 | tested | no `--token`; examples have no Bearer secrets |
| 10 | tested | `/agent`+bootstrap ≤16 KiB; context budget |
| 11 | tested | TestClient discovery→me without CLI package |
| 12 | tested | fixture upload/commit/readback; stale ETag 412 |
| 13 | tested | nested zip kept; traversal preview rejected |
| 14 | tested | 202 then job succeeded; 413/422 have machine code |
| 15 | tested mock | awaiting_approval; **remote_publish_verified=no** |

Status: public_discovery implemented+tested, not deployed. authenticated_read implemented+tested, not deployed. upload_pass local tests only. approval_id none. remote_publish_verified no.
