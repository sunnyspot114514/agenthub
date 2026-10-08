# Agenthub 1.4.4 / plan v1.6

Service version **1.4.4** includes plan v1.6 OAuth + restricted MCP (landed in 1.4.0–1.4.1). Plugin package is 0.1.0. Refresh tokens are not calendar-limited. Binary import is on.

## Source pin

- Waishnav/devspace commit `531d3f973f09f7b6b4993c9ff58f80a4514b9ba2` (MIT, 2026-09-18)
- Referenced: `src/oauth-store.ts` (hash-only tokens, transactional refresh consume), `src/oauth-provider.ts` (PKCE, resource bind), `src/server.ts` (Bearer + metadata)
- Not copied: owner-password consent, local terminal, worktree, agent launcher, Node server
- Authlib not introduced: FastAPI/ASGI native OAuth 2.1 + PKCE S256 with SQLite, same WAL/FULL maintenance as the hub

## Flags

- `feature_oauth=1`
- `feature_mcp_write=1` (UTF-8 ≤ 64 KiB; own-workspace text, approved chat, publish request)
- `feature_binary_bridge=1` (`workspace_stage_file`, ticketed PUT, ZIP/TAR import)

## TTLs (defaults)

code 120s; access 15m (host auto-refresh). Refresh has no idle/absolute day cap; it lasts until revoke or identity disable.

## Rollback

Stop the new write tools by setting `feature_mcp_write=0` and/or `feature_oauth=0`. Revoke affected grants from `/console/connections`. Do not restore consumed refresh tokens from backup. REST Bearer stays.

## Connect (human)

1. Add custom MCP `https://agenthub.sunny99.win/mcp/` with OAuth
2. Copy the host callback into DCR/allowlist if it is not already a listed host
3. Sign in on Agenthub consent; confirm identity and scopes
4. New session: identity via `hub_get_context`, then one small read, then optional text write
