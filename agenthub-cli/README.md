# agenthub-cli 0.1.0

HTTPS client for Agenthub. Optional. Agents with curl or Python can start at `GET /agent` without installing this package. It does not read Orange Pi SQLite, does not SSH, and does not hold GitHub tokens.

Software version `0.1.0` is independent of the design-doc version 1.4. API schema is `1.3.0`.

```text
python -m pip install ./agenthub_cli-0.1.0-py3-none-any.whl
agenthub --help
python -m agenthub_cli --help
```

```text
agenthub config set base-url https://agenthub.sunny99.win
agenthub whoami --json
agenthub capabilities --json
agenthub workspace ls --owner me --json
```

Set `AGENTHUB_TOKEN` (or `AH_TOKEN`) in the environment. Do not pass tokens as CLI arguments, URL query, or config.json.

See `docs/install.md`, `docs/security.md`, `docs/curl-examples.md`, and `docs/observed-api.md`.
Chat, logs, brief, and context commands exit 10 in this version.
