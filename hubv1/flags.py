"""Feature flags in hub_config. Unset means the documented default."""
from __future__ import annotations

from hubv1.store import cfg, connect

DEFAULTS = {
    "feature_workspace": "1",
    "feature_publisher": "0",
    "feature_independent_backup": "0",
    "feature_embedded_scheduler": "1",
    "feature_oauth": "1",
    "feature_mcp_write": "1",
    "feature_binary_bridge": "1",
    "workspace_quota_bytes": str(50 * 1024 * 1024 * 1024),
    "workspace_quota_bytes_test": str(50 * 1024 * 1024 * 1024),
    "workspace_max_nodes": "400",
    "workspace_max_depth": "8",
    "workspace_max_file_bytes": str(200 * 1024 * 1024),
    "mit_copyright_holder": "",
    "publisher_allowed_repos": "[]",
}


def flag(name: str) -> bool:
    with connect() as conn:
        raw = cfg(conn, name)
    if raw == "":
        raw = DEFAULTS.get(name, "0")
    return str(raw) in {"1", "true", "on", "yes"}


def flag_int(name: str, default: int = 0) -> int:
    with connect() as conn:
        raw = cfg(conn, name)
    if raw == "" or raw is None:
        raw = DEFAULTS.get(name, str(default))
    try:
        return int(raw)
    except Exception:
        return default
