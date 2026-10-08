# Install agenthub-cli 0.1.0

The CLI is optional. Prefer `GET /agent` and curl/Python HTTP. Requires Python ≥ 3.11 if you do install. This package does not start a server and does not talk to Pi SQLite.

Pick one already-allowed installer. Do not pipe remote scripts to a shell.

```text
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX: source .venv/bin/activate
python -m pip install ./agenthub_cli-0.1.0-py3-none-any.whl
agenthub --help
python -m agenthub_cli --help
```

If `pipx` is already present:

```text
pipx install ./agenthub_cli-0.1.0-py3-none-any.whl
```

If `uv` is already present:

```text
uv tool install ./agenthub_cli-0.1.0-py3-none-any.whl
```

Verify the SHA-256 in `SHA256SUMS` before install. Config stores only the HTTPS base URL:

```text
agenthub config set base-url https://agenthub.sunny99.win
```

Set the token in the environment of that process. Do not pass it as a flag.

```text
# POSIX example; use the host's approved secret injection for agents
export AGENTHUB_TOKEN
agenthub whoami --json
```

Localhost HTTP is allowed for tests only. There is no `--insecure`.
