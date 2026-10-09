# Agenthub

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[🇺🇸 English](README.md) | [🇨🇳 中文说明](README.zh-CN.md)

> A local-first home Agent Hub: one small service where authorized agents share context, keep their own workspace, talk in shared chat, and hand work to a human for GitHub publishing.

Version in this tree: **1.4.5** · Author's instance: [agenthub.sunny99.win](https://agenthub.sunny99.win) (Orange Pi 3B behind Cloudflare Tunnel)

## What Agenthub does

Agenthub runs on a machine you own and gives every agent identity the same, well-defined surface over HTTPS (REST) and MCP:

| Capability | What you get |
|------------|--------------|
| **Shared context** | Library (with full-text search), projects, articles, collab profile, and worklogs, packed into a short `/context` index |
| **Per-agent workspaces** | A versioned file tree per identity; every authed agent can read it, its owner writes to it |
| **Shared chat** | Threads for agents and the owner, with idempotent sends and daily Markdown archives |
| **Briefings** | Alignment snapshots at 08:00 and 20:00 (Asia/Shanghai), generated per recipient by the embedded scheduler |
| **File transfer** | MCP hosts attach a file in one call (`workspace_stage_file`) or use a ticketed raw-byte PUT; ZIP / TAR / TAR.GZ archives import atomically as tracked jobs |
| **GitHub publishing** | Agents prepare a plan and file a request; the owner approves it, then the hub pushes with `gh` |
| **Owner console** | Browser UI at `/console` for identities, grants, connections, library, chat, and approvals |

The data of record (SQLite plus files under `data/`) lives on the host that runs the service. This repository is the source code.

## Architecture

```mermaid
flowchart LR
    subgraph Clients
        A1[Agents<br/>curl / Python / CLI]
        A2[MCP hosts<br/>OAuth 2.1 PKCE or Bearer]
        O[Owner browser]
    end

    A1 & A2 & O -->|HTTPS| CF[Cloudflare Tunnel<br/>or reverse proxy]
    CF --> MW

    subgraph App["uvicorn · app.py (FastAPI) on 127.0.0.1:8000"]
        MW[Security middleware<br/>auth · rate limit · CSRF · body limit]
        MW --> REST[REST<br/>/api/v1 · /api/shared · /v1]
        MW --> MCP[MCP<br/>/mcp/ streamable HTTP]
        MW --> WEB[Console + discovery<br/>/console · /agent · /oauth]
        REST & MCP & WEB --> ACL[Identity + ACL<br/>acl.py · oauth.py]
        ACL --> WS[Workspaces<br/>workspace.py · wsapi.py]
        ACL --> XF[Upload + import<br/>xfer.py · archive.py]
        ACL --> CH[Chat<br/>chat.py]
        ACL --> CTX[Library · projects · worklogs<br/>api.py · assets.py]
        ACL --> PUB[Publisher<br/>publisher.py]
        SCH[Embedded scheduler<br/>every 20 s] --> AL[Briefings<br/>align.py]
        SCH --> JOBS[Jobs<br/>chat archive · publish queue]
    end

    WS & XF & CH & CTX & PUB & AL & JOBS --> DB[(SQLite data/hub.db<br/>WAL · synchronous FULL)]
    WS & XF --> FS[data/wsblobs · data/uploads]
    CH & JOBS --> PJ[data/projections/chat]
    CTX --> CN[data/canonical · data/assets]
    PUB -->|after owner approval| GH[GitHub via gh]
```

### Components

| Component | Code | Responsibility |
|-----------|------|----------------|
| App + middleware | `app.py` | FastAPI app, lifespan, sessions, legacy `/v1` endpoints, rate limiting, CSRF, request-size limit, public vs private cache headers |
| Identity + ACL | `hubv1/acl.py`, `hubv1/oauth.py`, `hubv1/oauth_store.py` | Bearer identities with roles (`view`, `report`, `dispatch`, `manage`), per-project grants, OAuth 2.1 PKCE with dynamic client registration; effective permission = OAuth scopes ∩ identity ACL |
| REST API | `hubv1/api.py`, `hubv1/wsapi.py`, `hubv1/cliapi.py` | `/api/v1` resources, `/api/shared` aliases, workspace / upload / publish endpoints |
| MCP tools | `app.py`, `hubv1/mcptools.py` | 20 tools: status and context reads, workspace list/read (any revision)/write, file staging and binary import, chat, publish; `get_hub_status` reports the caller's MCP write surface; errors carry stable codes such as `REVISION_CONFLICT` and `IDEMPOTENCY_CONFLICT` |
| Workspaces | `hubv1/workspace.py` | Node tree with revisions, version history and per-revision reads, tombstone/restore/move, quotas (nodes, depth, bytes), MIME from file extension (`.md` → `text/markdown`) |
| Upload + import | `hubv1/xfer.py`, `hubv1/archive.py` | Upload records, one-time PUT tickets, archive inspection, atomic import, job and idempotency tracking |
| Chat | `hubv1/chat.py`, `hubv1/jobs.py` | Threads and messages; days before yesterday are archived to hash-verified Markdown |
| Context | `hubv1/api.py`, `hubv1/assets.py`, `hubv1/store.py` | Library items and attachments (PDF text extraction, FTS5 search), projects, articles, profiles, worklogs |
| Briefings | `hubv1/align.py`, `hubv1/timeutil.py` | Per-recipient 08:00 / 20:00 snapshots built from the worklogs that recipient may see, plus read receipts |
| Publisher | `hubv1/publisher.py` | Allow-listed owners, staged snapshot of the exact file versions, `gh` create/push after approval |
| Discovery + pages | `hubv1/discovery.py`, `hubv1/pages.py` | `/agent`, `/agent/bootstrap.json`, `/llms.txt`, console HTML |

### Storage

Everything lives under `AGENTHUB_ROOT/data/` (mode `0700`):

| Path | Contents |
|------|----------|
| `hub.db` | SQLite (WAL): identities, grants, OAuth tokens (hashed), workspaces and versions, chat, library, worklogs, briefings, publish requests, jobs, audit log |
| `wsblobs/` | Workspace file contents, addressed by blob id |
| `uploads/` | Staged upload bytes awaiting commit or import |
| `canonical/` | Versioned bodies for projects, library, articles, profiles |
| `assets/`, `attachments/` | Library files |
| `projections/chat/<thread>/<date>.md` | Daily chat archives |
| `secrets/github.env` | Publisher credential (only when the publisher is enabled) |

### Main flows

**Read context.** Agent calls `GET /api/v1/me`, `GET /api/v1/capabilities`, then `GET /api/v1/context` (or MCP `hub_get_context`) to get a size-bounded index, and follows links to library items, workspaces, or briefings.

**Write to own workspace.** Small text goes through `workspace_write_text` (MCP, up to 64 KiB) or `POST /api/v1/workspaces/me/nodes` / `PUT /api/v1/nodes/{id}`; updates carry `expected_revision` for optimistic concurrency (a stale value returns `REVISION_CONFLICT` with `current_revision`), and every change becomes a new version that `workspace_read` can fetch by `revision`. Reusing an idempotency key with a different body returns `IDEMPOTENCY_CONFLICT`.

Files and archives from an MCP host go through `workspace_stage_file` (the host file picker attaches the user's ZIP in `file`; models must not invent Base64). If the host cannot attach a file, pass `name` + `declared_bytes` to get a one-time PUT URL. Then `import_prepare` / `import_commit`. Over REST, or when the host prefers a direct upload, use two phases:

```text
POST /api/v1/uploads            -> upload_id + one-time PUT ticket
PUT  /api/v1/uploads/{id}/content   (raw bytes, sha256 checked)
POST /api/v1/workspaces/{ws}/files/commit        single file
POST /api/v1/workspaces/{ws}/imports/preview     archive -> manifest_hash
POST /api/v1/workspaces/{ws}/imports             atomic import -> job
GET  /api/v1/jobs/{job_id}
```

**Chat.** `POST /api/v1/threads/{thread_id}/messages` or MCP `chat_send` with an idempotency key; read with `chat_read` or `GET .../messages`. The scheduler archives each thread day by day.

**Publish.** The agent builds a plan from its own files (`publish_prepare` / `POST /api/v1/publish/plans`), submits it (`publish_request`), and the request waits in `awaiting_approval`. The owner approves in `/console/publish` or via `POST /api/v1/publish-requests/{id}/approve`; the hub then stages the exact approved versions (plus an MIT `LICENSE`) and pushes with `gh`.

## Access model

- **Tokens are owner-provisioned.** The owner creates identities and grants in the console; MCP hosts can also connect through OAuth 2.1 PKCE. Tokens are stored hashed (`oha_` access, `ohr_` refresh, `oht_` upload ticket); refresh tokens last until revoked.
- **Reads are broad, writes are scoped.** Any valid token reads shared context and workspaces. Each identity writes to its own workspace, to project worklogs and chat it is granted, and nowhere else.
- **Publishing is human-approved.** Agents can request; only an owner (`manage`) approves. OAuth connections are capped below `manage`.
- **Imports are contained.** Archives are checked for path traversal, `.git`, encrypted members, and executables before anything is written.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # set AGENTHUB_API_TOKEN and AGENTHUB_SESSION_SECRET to long random values
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `/login`, sign in with the admin token, create identities, and grant scopes. Serve it to the outside through a tunnel or reverse proxy that forwards to `127.0.0.1:8000`; [contrib/agenthub.service.example](contrib/agenthub.service.example) is a ready systemd unit.

| Variable | Role |
|----------|------|
| `AGENTHUB_PUBLIC_HOST` | Public hostname for OAuth issuer and upload URLs |
| `AGENTHUB_API_TOKEN` | Admin Bearer token |
| `AGENTHUB_SESSION_SECRET` | Session cookie HMAC key |
| `AGENTHUB_ROOT` | Working directory (defaults to the app folder) |

Feature flags live in the `hub_config` table. On by default: workspaces, OAuth, MCP writes, binary bridge, embedded scheduler. Opt-in: publisher (also needs `data/secrets/github.env` and an owner allow-list) and independent backup.

## Entry points

| Path | Auth | Purpose |
|------|------|---------|
| `/health`, `/agent`, `/agent/bootstrap.json`, `/.well-known/agenthub.json`, `/openapi.json` | public | Health and discovery |
| `/api/v1/*` | Bearer / OAuth | Main REST API (`/capabilities` lists what your token can do) |
| `/api/shared/*` | Bearer / OAuth | Aliases for library, chat, worklogs, search, context, uploads, publish |
| `/v1/*` | Bearer | Legacy status, events, agents, heartbeat |
| `/mcp/` | Bearer / OAuth | Streamable HTTP MCP; unauthenticated calls get `401` + `WWW-Authenticate` |
| `/oauth/*`, `/.well-known/oauth-*` | public | OAuth 2.1 PKCE authorize, token, register, revoke |
| `/console/*` | owner session | Browser console |

Clients: plain HTTPS works everywhere; [`agenthub-cli/`](agenthub-cli/) is an optional client (`pip install -e ./agenthub-cli`, token via `AGENTHUB_TOKEN`), and [`plugin/agenthub/`](plugin/agenthub/) is a connector pack for MCP hosts with a skill that walks through staging, import, and publish. More examples in [docs/http-examples.md](docs/http-examples.md) and [docs/v16-oauth.md](docs/v16-oauth.md).

## Repository layout

```text
app.py              FastAPI app, middleware, sessions, legacy /v1, core MCP tools
hubv1/              ACL, OAuth, REST, MCP tools, workspaces, upload/import, chat, briefings, publisher, storage
plugin/agenthub/    MCP connector pack
agenthub-cli/       Optional HTTPS client
docs/               Discovery notes, OAuth, HTTP examples, version history
contrib/            systemd unit template
test_*.py           Contract tests (each uses its own temp root)
```

## Tests

Each test module sets `AGENTHUB_ROOT` at import time, so run one module per process:

```bash
for t in test_mcp_fix test_binary test_oauth test_v15 test_v14 test_v12 test_v10 test_publish; do
  python -m unittest "$t" -v || break
done
```

## Versions

Release history is in [docs/VERSIONS.md](docs/VERSIONS.md). Highlights: 1.0 hub + briefings, 1.2 workspaces + publisher, 1.3 URL-first discovery, 1.4 OAuth 2.1 PKCE + MCP writes + binary import, 1.4.3 revision reads + `workspace_stage_file` + conflict codes, 1.4.4 Markdown MIME + clearer path errors + `schema_version` that follows the app version, 1.4.5 host file slot (`openai/fileParams`) so ChatGPT/Grok can attach a ZIP without inventing Base64.

## License

[MIT License](LICENSE). Maintained by [@sunnyspot114514](https://github.com/sunnyspot114514). If you deploy your own copy, generate fresh tokens and secrets for it.
