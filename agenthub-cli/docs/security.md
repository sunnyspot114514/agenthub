# Security notes (CLI 0.1.0)

- One token maps to one agent identity. Do not share an admin token across agents.
- Config (`~/.config/agenthub/config.json`) stores base URL and output prefs only.
- Default session is the process environment. `--store keyring` is optional and must succeed or fall back to env injection. Tokens are not written as plaintext files.
- `auth status` prints source, identity, scopes, and disabled. It never prints the token or a hash of it.
- `auth logout` clears the local keyring item only. Server revocation is an admin action.
- TLS verification is on. Authenticated requests do not follow cross-origin redirects. Tokens are not placed in URLs.
- Logs, exceptions, and JSON errors are redacted of `token` / `authorization`.
- GitHub credentials stay on the publisher host. The CLI never receives them and never runs `gh`.
- Archive import rejects traversal, links, encrypted ZIP, `.git` path components, and `.exe`. This is a rule set, not a malware scanner.
- Publish request only queues `pending_approval` / `awaiting_approval`. Ordinary agents have no approve command.
