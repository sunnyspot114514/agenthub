"""Explicit live migration: workspaces for all identities.

Formal agents get 32MiB own-write. Test agents get own-write at 4MiB.
Does not grant worklog:write on hub-shared, does not enable publisher, does not create GitHub credentials.
"""
from __future__ import annotations

from hubv1.acl import add_scopes, load_grant
from hubv1.store import audit, connect, init_v1, refresh_paths
from hubv1.workspace import ensure_all_workspaces

FORMAL = ("agent-1", "agent-2", "agent-3", "agent-4")
TEST = ("agent-test", "agent-test-short")
TEST_QUOTA = 4 * 1024 * 1024


def main() -> None:
    refresh_paths()
    with connect() as conn:
        init_v1(conn)
        n = ensure_all_workspaces(conn)
        audit(conn, "admin", "workspace.migrate", "all", "", f"ensured={n}")
        for aid in TEST:
            conn.execute(
                "UPDATE workspaces SET quota_bytes=? WHERE owner_agent_id=?",
                (TEST_QUOTA, aid),
            )
            audit(conn, "admin", "workspace.quota", aid, "", f"quota_bytes={TEST_QUOTA}")
    for aid in FORMAL + TEST:
        g = load_grant(aid)
        if not g:
            print("skip_no_grant", aid)
            continue
        add_scopes(aid, ["workspace:write:own"], actor_id="admin")
        print("granted_workspace_write_own", aid)
    with connect() as conn:
        for r in conn.execute(
            "SELECT owner_agent_id, display_slug, quota_bytes FROM workspaces ORDER BY display_slug"
        ):
            print("workspace", r["owner_agent_id"], r["display_slug"], "quota", r["quota_bytes"])
        for r in conn.execute("SELECT agent_id, scopes FROM agent_grants ORDER BY agent_id"):
            print("grant", r["agent_id"], r["scopes"])
    print("publisher_still_off")
    print("no_project_worklog_write")


if __name__ == "__main__":
    main()
