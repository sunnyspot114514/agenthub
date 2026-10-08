# Versions

Software versions (`APP_VERSION`) are independent of internal design-doc numbers.

| Version | What landed |
|---------|-------------|
| 1.0 | FastAPI hub, SQLite WAL, identities, shared chat, library, 08:00/20:00 alignment snapshots |
| 1.1 | Shared vs collab profiles, HTML/MD/JSON/MCP under the same ACL |
| 1.2 | Per-identity workspaces, ZIP extract in console, GitHub publisher (request → human approve → push) |
| 1.3 | URL-first discovery (`/agent`, `/agent/bootstrap.json`) |
| 1.4.0 | OAuth 2.1 PKCE, restricted MCP write tools (own-workspace text, approved chat, publish request) |
| 1.4.1 | Refresh tokens last until revoke or identity disable (no 7/30-day calendar cap) |
| 1.4.2 | Ticketed binary PUT, ZIP/TAR import over MCP, `api_version` aligned with hub status |
| 1.4.3 | `workspace_read` honors `revision`; missing revision errors; `IDEMPOTENCY_CONFLICT`; `workspace_stage_file`; MCP surface `restricted`; `REVISION_CONFLICT` |
| **1.4.4** | `.md` stored as `text/markdown`; path-traversal errors no longer say “archive”; JSON envelope `schema_version` follows `APP_VERSION`; OAuth notes match 1.4.4 (`feature_binary_bridge=1`) |

Flags default on in 1.4.4: `feature_workspace`, `feature_oauth`, `feature_mcp_write`, `feature_binary_bridge`. Publisher and independent backup stay off until the operator enables them.
