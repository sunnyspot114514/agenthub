# Agenthub OAuth notes (plan v1.6)

Historical notes from the 1.4.0/1.4.1 OAuth cut. Current service version is 1.4.2; see [VERSIONS.md](VERSIONS.md). Plugin package is 0.1.0. Refresh tokens are not calendar-limited.

## Source pin

- Waishnav/devspace commit `531d3f973f09f7b6b4993c9ff58f80a4514b9ba2` (MIT, 2026-09-18)
- Referenced: `src/oauth-store.ts` (hash-only tokens, transactional refresh consume), `src/oauth-provider.ts` (PKCE, resource bind), `src/server.ts` (Bearer + metadata)
- Not copied: owner-password consent, local terminal, worktree, agent launcher, Node server
- Authlib not introduced: FastAPI/ASGI native OAuth 2.1 + PKCE S256 with SQLite, same WAL/FULL maintenance as the hub

## Flags

- `feature_oauth=1`
- `feature_mcp_write=1` (UTF-8 ≤ 64 KiB)
- `feature_binary_bridge=1` as of 1.4.2 (ticketed PUT + ZIP/TAR import; still no arbitrary URL fetch)

## TTLs (defaults)

code 120s; access 15m (host auto-refresh). Refresh has no idle/absolute day cap; it lasts until revoke or identity disable.

## Rollback

Stop the new write tools by setting `feature_mcp_write=0` and/or `feature_oauth=0`. Revoke affected grants from `/console/connections`. Do not restore consumed refresh tokens from backup. REST Bearer stays.

## Connect (human)

1. Add custom MCP `https://agenthub.sunny99.win/mcp/` with OAuth
2. Copy the host callback into DCR/allowlist if it is not already a listed host
3. Sign in on Agenthub consent; confirm identity and scopes
4. New session: identity via `hub_get_context`, then one small read, then optional text write
