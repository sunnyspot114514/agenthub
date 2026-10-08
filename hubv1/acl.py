from __future__ import annotations

import json
from typing import Any, Optional

from hubv1.store import connect, dumps

DEFAULT_SCOPES = {
    "view": ["library:read", "alignment:read", "chat:read", "article:read", "project:read"],
    "report": [
        "library:read",
        "alignment:read",
        "chat:read",
        "article:read",
        "project:read",
        "worklog:write",
        "chat:write",
        "article:write",
        "proposal:write",
    ],
    "dispatch": ["worklog:write", "chat:write"],
    "manage": ["*"],
}

DEFAULT_SHARE = ["done", "results", "blockers", "next", "papers", "drafts"]
PRIVATE_VIS = {"owner", "owner_only", "self", "private", "self_only"}


def _parse_acl(acl: Any) -> dict[str, Any]:
    if not acl:
        return {"visibility": "shared"}
    if isinstance(acl, str):
        try:
            acl = json.loads(acl)
        except Exception:
            return {"visibility": "shared"}
    return acl if isinstance(acl, dict) else {"visibility": "shared"}


class Access:
    def __init__(self, principal, grant: Optional[dict[str, Any]]):
        self.p = principal
        self.grant = grant or {}
        self.revoked = bool(self.grant.get("revoked_at"))
        self.project_ids = set(self.grant.get("project_ids") or [])
        self.scopes = set(self.grant.get("scopes") or [])
        self.share_classes = set(self.grant.get("share_classes") or DEFAULT_SHARE)
        self.grant_version = int(self.grant.get("version") or 0)

    @property
    def oauth_bound(self) -> bool:
        return bool(getattr(self.p, "oauth_grant_id", None))

    @property
    def manage(self) -> bool:
        if self.oauth_bound:
            return False
        return self.p.has("manage")

    def is_authed_reader(self) -> bool:
        if self.revoked:
            return False
        if self.oauth_bound:
            oauth = set(getattr(self.p, "oauth_scopes", None) or [])
            return "hub:read" in oauth or any(s.endswith(":read") for s in oauth)
        return self.manage or self.p.has("view") or self.p.has("report")

    def has_scope(self, scope: str) -> bool:
        if self.revoked:
            return False
        if self.oauth_bound:
            oauth = set(getattr(self.p, "oauth_scopes", None) or [])
            if scope.endswith(":read") or scope in {"view", "library:read", "alignment:read", "chat:read", "article:read", "project:read"}:
                return "hub:read" in oauth or scope in oauth
            if scope == "hub:read":
                return "hub:read" in oauth
            return scope in oauth
        if self.manage:
            return True
        if scope.endswith(":read") and self.is_authed_reader():
            return True
        return "*" in self.scopes or scope in self.scopes or self.p.has(scope)

    def in_project(self, project_id: str) -> bool:
        if self.manage:
            return True
        if self.revoked:
            return False
        return bool(project_id) and project_id in self.project_ids

    def _project_visibility(self, project_id: str) -> str:
        if not project_id:
            return "shared"
        with connect() as conn:
            row = conn.execute("SELECT acl FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if not row:
            return "shared"
        return _parse_acl(row["acl"]).get("visibility") or "shared"

    def can_read_project(self, project_id: str) -> bool:
        if not self.is_authed_reader():
            return False
        if self.manage:
            return True
        vis = self._project_visibility(project_id)
        if vis in PRIVATE_VIS:
            return self.in_project(project_id)
        return True

    def can_write_worklog(self, project_id: str) -> bool:
        return self.in_project(project_id) and self.has_scope("worklog:write")

    def can_write_article(self, project_id: str) -> bool:
        return self.in_project(project_id) and self.has_scope("article:write")

    def can_write_own_workspace(self) -> bool:
        if self.manage:
            return True
        if self.revoked:
            return False
        return self.has_scope("workspace:write:own")

    def can_chat(self, project_id: Optional[str], write: bool = False) -> bool:
        if write:
            if not self.has_scope("chat:write"):
                return False
            if project_id is None:
                return self.manage
            return self.in_project(project_id)
        if not self.is_authed_reader():
            return False
        if project_id is None:
            return True
        return self.can_read_project(project_id)

    def acl_ok(self, acl: Any) -> bool:
        if not self.is_authed_reader():
            return False
        parsed = _parse_acl(acl)
        vis = parsed.get("visibility") or "shared"
        principals = set(parsed.get("principals") or [])
        if vis in PRIVATE_VIS:
            return self.manage or self.p.kind in {"admin"} or self.p.id in principals
        return True

    def can_read_record(self, acl: Any, project_id: str | None = None) -> bool:
        if not self.is_authed_reader():
            return False
        parsed = _parse_acl(acl)
        vis = parsed.get("visibility") or "shared"
        if vis in PRIVATE_VIS:
            return self.acl_ok(acl)
        if project_id and self.can_read_project(project_id):
            return True
        return self.acl_ok(acl)

    def filter_summary(self, summary: dict[str, Any], source_share: set[str]) -> dict[str, str]:
        if not self.is_authed_reader():
            return {}
        allowed = source_share or set(DEFAULT_SHARE)
        out = {}
        mapping = {"done": "done", "results": "result", "blockers": "blocker", "next": "next"}
        for cls, field in mapping.items():
            if cls in allowed or field in allowed:
                val = (summary or {}).get(field) or (summary or {}).get(cls) or ""
                if val:
                    out[field] = val
        return out


def load_grant(agent_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM agent_grants WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["project_ids"] = json.loads(d["project_ids"] or "[]")
    d["scopes"] = json.loads(d["scopes"] or "[]")
    d["share_classes"] = json.loads(d["share_classes"] or "[]")
    d["roles"] = json.loads(d["roles"] or "[]")
    return d


def access_for(principal) -> Access:
    return Access(principal, load_grant(principal.id))


def grant_acl_version() -> str:
    with connect() as conn:
        rows = conn.execute("SELECT agent_id, version, revoked_at FROM agent_grants").fetchall()
    blob = dumps([{"id": r["agent_id"], "v": r["version"], "r": r["revoked_at"]} for r in rows])
    from hubv1.store import sha256_text

    return sha256_text(blob)[:16]


def upsert_grant(
    agent_id: str,
    *,
    provider: str = "",
    roles: list[str],
    project_ids: list[str],
    scopes: Optional[list[str]] = None,
    share_classes: Optional[list[str]] = None,
    revoked_at: Optional[str] = None,
) -> dict[str, Any]:
    if scopes is None:
        scopes = []
        for r in roles:
            scopes.extend(DEFAULT_SCOPES.get(r, []))
        scopes = sorted(set(scopes))
    if share_classes is None:
        share_classes = list(DEFAULT_SHARE)
    from hubv1.timeutil import now_iso

    with connect() as conn:
        prev = conn.execute("SELECT version FROM agent_grants WHERE agent_id=?", (agent_id,)).fetchone()
        version = (prev["version"] + 1) if prev else 1
        conn.execute(
            """
            INSERT INTO agent_grants(agent_id, provider, roles, project_ids, scopes, share_classes, version, revoked_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(agent_id) DO UPDATE SET
              provider=excluded.provider, roles=excluded.roles, project_ids=excluded.project_ids,
              scopes=excluded.scopes, share_classes=excluded.share_classes, version=excluded.version,
              revoked_at=excluded.revoked_at, updated_at=excluded.updated_at
            """,
            (
                agent_id,
                provider,
                dumps(roles),
                dumps(project_ids),
                dumps(scopes),
                dumps(share_classes),
                version,
                revoked_at,
                now_iso(),
            ),
        )
    return load_grant(agent_id) or {}


def add_scopes(agent_id: str, extra: list[str], *, actor_id: str = "system") -> dict[str, Any]:
    """Append write scopes without recomputing from roles (does not expand chat:write into worklog:write)."""
    g = load_grant(agent_id)
    if not g:
        return {}
    scopes = list(g.get("scopes") or [])
    changed = False
    for s in extra:
        if s not in scopes:
            scopes.append(s)
            changed = True
    if not changed:
        return g
    return upsert_grant(
        agent_id,
        provider=g.get("provider") or "",
        roles=list(g.get("roles") or ["view", "report"]),
        project_ids=list(g.get("project_ids") or []),
        scopes=scopes,
        share_classes=list(g.get("share_classes") or list(DEFAULT_SHARE)),
        revoked_at=g.get("revoked_at"),
    )


def project_acl(project_id: str, visibility: str = "shared") -> dict[str, Any]:
    return {"projects": [project_id], "principals": ["owner"], "visibility": visibility}
