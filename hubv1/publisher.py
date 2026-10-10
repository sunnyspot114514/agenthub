"""Controlled GitHub publish. Agents request; only admin approves. Token never goes to workspace/chat/logs."""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from hubv1.flags import flag
from hubv1.settings import copyright_holder_default, git_author_email, git_author_name, license_year
from hubv1.store import audit, cfg, connect, data_dir, dumps, ensure_dirs, loads, new_id, sha256_bytes
from hubv1.timeutil import now_iso
from hubv1 import workspace as ws

REPO_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,99}$")
SECRET_RE = re.compile(rb"gho_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}")
WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/", re.I)
BRANCH_BAD = re.compile(r"[\x00-\x20~^:?*\[\\]|@{")


def valid_git_branch(name: str) -> bool:
    """Match `git check-ref-format --branch` well enough to reject unsafe refs."""
    if not name or name in {".", "..", "@"} or len(name) > 255:
        return False
    if name.startswith("-") or name.startswith("/") or name.endswith("/") or name.endswith("."):
        return False
    if ".." in name or "//" in name or BRANCH_BAD.search(name):
        return False
    for part in name.split("/"):
        if not part or part.startswith(".") or part.endswith(".") or part.endswith(".lock"):
            return False
    return True


def publisher_enabled() -> bool:
    return flag("feature_publisher")


def secrets_dir() -> Path:
    ensure_dirs()
    path = data_dir() / "secrets"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def load_github_token() -> Optional[str]:
    path = secrets_dir() / "github.env"
    if not path.is_file():
        return None
    try:
        if path.is_symlink():
            return None
    except Exception:
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() in {"GH_TOKEN", "GITHUB_TOKEN"} and v.strip():
            return v.strip().strip('"').strip("'")
    return None


def allowed_owners() -> list[str]:
    with connect() as conn:
        raw = cfg(conn, "publisher_allowed_owners") or "[]"
    try:
        items = json.loads(raw)
    except Exception:
        items = []
    return [str(x).strip() for x in items if str(x).strip()]


def copyright_holder() -> str:
    with connect() as conn:
        return (cfg(conn, "mit_copyright_holder") or "").strip()


def mit_text(year: str, holder: str) -> str:
    return (
        f"MIT License\n\nCopyright (c) {year} {holder}\n\n"
        "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
        'of this software and associated documentation files (the "Software"), to deal\n'
        "in the Software without restriction, including without limitation the rights\n"
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
        "copies of the Software, and to permit persons to whom the Software is\n"
        "furnished to do so, subject to the following conditions:\n\n"
        "The above copyright notice and this permission notice shall be included in all\n"
        "copies or substantial portions of the Software.\n\n"
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
        "SOFTWARE.\n"
    )


def _set_state(conn, request_id: str, state: str, result: Optional[dict] = None) -> None:
    now = now_iso()
    if result is None:
        conn.execute("UPDATE publish_requests SET state=?, updated_at=? WHERE request_id=?", (state, now, request_id))
        return
    conn.execute(
        "UPDATE publish_requests SET state=?, result_json=?, updated_at=? WHERE request_id=?",
        (state, dumps(result), now, request_id),
    )


def _norm_publish_name(path: str) -> str:
    rel = (path or "").replace("\\", "/").strip("/")
    if not rel or rel in {".", ".."} or ".." in Path(rel).parts:
        return ""
    return rel


def _own_workspace_id(agent_id: str) -> Optional[str]:
    mine = ws.workspace_of(agent_id)
    return mine["workspace_id"] if mine else None


def _validate_nodes(acc, node_ids: list[str]) -> list[dict[str, Any]]:
    out = []
    mine = _own_workspace_id(acc.p.id)
    for nid in node_ids:
        node = ws.get_node(nid)
        if not node or node.get("deleted_at") or node["kind"] != "file":
            raise ValueError(f"node not publishable: {nid}")
        if not acc.manage:
            if not mine or node["workspace_id"] != mine:
                raise PermissionError("can only publish files from your own workspace")
        rel = ws.node_relpath(nid) or node["name"]
        if WORKFLOW_RE.search(rel.replace("\\", "/")) or rel.endswith(".git"):
            raise ValueError("workflows and git metadata cannot be published in v1")
        data, mime, fname = ws.file_payload(nid)
        if SECRET_RE.search(data):
            raise ValueError("refusing to publish: secret-like pattern in file")
        out.append({"node_id": nid, "name": rel or fname, "data": data, "mime": mime, "version_id": node["current_version_id"]})
    return out


def actor_can_request(acc) -> bool:
    return bool(acc.has_scope("publish:request") or acc.manage)


def create_request(
    acc,
    *,
    node_ids: list[str],
    target_owner: str,
    repo: str,
    branch: str,
    create_repo: bool,
    request_id: str = "",
    publish_paths: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    if not publisher_enabled():
        raise PermissionError("publisher disabled")
    if not acc.has_scope("publish:request") and not acc.manage:
        raise PermissionError("forbidden")
    if not node_ids:
        raise ValueError("empty selection")
    owner = (target_owner or "").strip()
    name = (repo or "").strip()
    if owner.lower() not in {o.lower() for o in allowed_owners()}:
        raise PermissionError("owner not on allowlist")
    if not REPO_RE.fullmatch(name) or name in {".", ".."}:
        raise ValueError("bad repo name")
    br = (branch or "main").strip()
    if not valid_git_branch(br):
        raise ValueError("bad branch name")
    if create_repo and not copyright_holder():
        raise PermissionError("MIT copyright holder not configured")
    files = _validate_nodes(acc, node_ids)
    if publish_paths:
        for item in files:
            override = _norm_publish_name(publish_paths.get(item["node_id"]) or "")
            if not override:
                raise ValueError("missing publish path")
            item["name"] = override
    snap = {
        "node_ids": [f["node_id"] for f in files],
        "version_ids": [f["version_id"] for f in files],
        "names": [f["name"] for f in files],
        "actor": acc.p.id,
        "sha256": sha256_bytes(b"".join(f["version_id"].encode() for f in files)),
    }
    rid = new_id("pub")
    now = now_iso()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO publish_requests(
              request_id, actor_id, source_json, target_owner, repo, branch, create_repo,
              snapshot_hash, state, created_at, updated_at, approved_by, approved_at, result_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                rid,
                acc.p.id,
                dumps(snap),
                owner,
                name,
                br,
                1 if create_repo else 0,
                snap["sha256"],
                "awaiting_approval",
                now,
                now,
                "",
                None,
                "",
            ),
        )
        audit(conn, acc.p.id, "publish.request", rid, request_id, "awaiting_approval")
    return {"request_id": rid, "state": "awaiting_approval", "create_repo": bool(create_repo), "repo": f"{owner}/{name}"}


def get_request(request_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM publish_requests WHERE request_id=?", (request_id,)).fetchone()
    return dict(row) if row else None


def list_requests(acc) -> list[dict[str, Any]]:
    with connect() as conn:
        if acc.manage:
            rows = conn.execute("SELECT * FROM publish_requests ORDER BY created_at DESC LIMIT 50").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM publish_requests WHERE actor_id=? ORDER BY created_at DESC LIMIT 50",
                (acc.p.id,),
            ).fetchall()
    return [dict(r) for r in rows]


def decide(acc, request_id: str, *, approve: bool, request_id_http: str = "") -> dict[str, Any]:
    if not acc.manage:
        raise PermissionError("forbidden")
    with connect() as conn:
        row = conn.execute("SELECT * FROM publish_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            raise KeyError("not found")
        if row["state"] not in {"awaiting_approval", "prepared"}:
            raise RuntimeError("not awaiting")
        now = now_iso()
        state = "approved" if approve else "cancelled"
        conn.execute(
            "UPDATE publish_requests SET state=?, approved_by=?, approved_at=?, updated_at=? WHERE request_id=?",
            (state, acc.p.id, now, now, request_id),
        )
        audit(conn, acc.p.id, "publish.decide", request_id, request_id_http, state)
    if approve:
        try:
            process_queue()
        except Exception:
            pass
    return {"request_id": request_id, "state": state}


def gh_bin() -> str:
    for p in (data_dir().parent / "bin" / "gh", Path("/usr/bin/gh"), Path("/usr/local/bin/gh")):
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    found = shutil.which("gh")
    return found or "gh"


def _gh_env(token: str, config_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    env["GITHUB_TOKEN"] = token
    env["GH_CONFIG_DIR"] = str(config_dir)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    gitconfig = config_dir / "gitconfig"
    if not gitconfig.is_file():
        gitconfig.write_text("", encoding="utf-8")
    try:
        os.chmod(gitconfig, 0o600)
    except Exception:
        pass
    env["GIT_CONFIG_GLOBAL"] = str(gitconfig)
    env.pop("GIT_ASKPASS", None)
    env.pop("GH_ENTERPRISE_TOKEN", None)
    return env


def _run(cmd: list[str], *, cwd: Optional[Path], env: dict[str, str], timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True, timeout=timeout, check=False)
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    secrets = [env.get("GH_TOKEN") or "", env.get("_AH_REDACT") or ""]
    for secret in secrets:
        if secret:
            out = out.replace(secret, "[redacted]")
            err = err.replace(secret, "[redacted]")
    return proc.returncode, out, err


def _write_staging(files: list[dict[str, Any]], holder: str) -> Path:
    root = data_dir() / "publish-staging"
    root.mkdir(mode=0o700, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="pub-", dir=str(root)))
    os.chmod(staging, 0o700)
    root = staging.resolve()
    for item in files:
        rel = (item.get("name") or "").replace("\\", "/").strip("/")
        if not rel or rel in {".", ".."} or ".." in Path(rel).parts:
            raise ValueError("bad filename")
        dest = (staging / rel).resolve()
        try:
            dest.relative_to(root)
        except ValueError as exc:
            raise ValueError("bad filename") from exc
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(item["data"])
        os.chmod(dest, 0o600)
    (staging / "LICENSE").write_text(mit_text(license_year(), holder), encoding="utf-8")
    os.chmod(staging / "LICENSE", 0o600)
    return staging


def execute_one(row: dict[str, Any]) -> dict[str, Any]:
    token = load_github_token()
    if not token:
        with connect() as conn:
            _set_state(
                conn,
                row["request_id"],
                "awaiting_repo_access",
                {"reason": "publisher credentials missing"},
            )
        return {"ok": False, "reason": "no_token"}
    holder = copyright_holder()
    if row.get("create_repo") and not holder:
        with connect() as conn:
            _set_state(conn, row["request_id"], "failed", {"reason": "copyright holder missing"})
        return {"ok": False, "reason": "no_holder"}
    snap = loads(row["source_json"] or "{}", {})
    node_ids = snap.get("node_ids") or []
    names = snap.get("names") or []
    files = []
    for index, nid in enumerate(node_ids):
        node = ws.get_node(nid)
        if not node:
            with connect() as conn:
                _set_state(conn, row["request_id"], "failed", {"reason": "source node missing"})
            return {"ok": False, "reason": "missing_node"}
        if node["current_version_id"] not in (snap.get("version_ids") or [node["current_version_id"]]):
            with connect() as conn:
                _set_state(conn, row["request_id"], "failed", {"reason": "source changed after approval; re-review"})
            return {"ok": False, "reason": "snapshot_changed"}
        data, mime, fname = ws.file_payload(nid)
        pub_name = _norm_publish_name(names[index] if index < len(names) else "") or ws.node_relpath(nid) or fname
        files.append({"name": pub_name, "data": data})
    result = loads(row.get("result_json") or "", {}) or {}
    owner, repo, branch = row["target_owner"], row["repo"], row["branch"] or "main"
    config_dir = secrets_dir() / "gh-config"
    config_dir.mkdir(mode=0o700, exist_ok=True)
    env = _gh_env(token, config_dir)
    staging = None
    try:
        if int(row["create_repo"] or 0) and not result.get("repository_id"):
            with connect() as conn:
                _set_state(conn, row["request_id"], "creating_repo", result)
            code, out, err = _run(
                [
                    gh_bin(),
                    "api",
                    "-X",
                    "POST",
                    "/user/repos",
                    "-f",
                    f"name={repo}",
                    "-F",
                    "private=false",
                    "-F",
                    "auto_init=false",
                ],
                cwd=None,
                env=env,
                timeout=45,
            )
            if code != 0:
                with connect() as conn:
                    _set_state(
                        conn,
                        row["request_id"],
                        "failed",
                        {"reason": "create_repo_failed", "detail": (err or out)[:400]},
                    )
                return {"ok": False, "reason": "create_failed"}
            info = json.loads(out)
            if info.get("private") or str(info.get("owner", {}).get("login") or "").lower() != owner.lower():
                with connect() as conn:
                    _set_state(conn, row["request_id"], "failed", {"reason": "created repo visibility or owner mismatch"})
                return {"ok": False, "reason": "mismatch"}
            result.update(
                {
                    "repository_id": info.get("id"),
                    "full_name": info.get("full_name"),
                    "html_url": info.get("html_url"),
                    "public": not info.get("private"),
                }
            )
            with connect() as conn:
                _set_state(conn, row["request_id"], "pushing", result)
        else:
            with connect() as conn:
                _set_state(conn, row["request_id"], "pushing", result)
        staging = _write_staging(files, holder or copyright_holder_default())
        git_c = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            f"user.name={git_author_name()}",
            "-c",
            f"user.email={git_author_email()}",
        ]
        basic = base64.b64encode(f"x-access-token:{token}".encode("ascii")).decode("ascii")
        env["_AH_REDACT"] = basic
        push_c = git_c + [
            "-c",
            "credential.helper=",
            "-c",
            f"http.extraHeader=Authorization: Basic {basic}",
        ]
        for cmd in (
            git_c + ["init", "-b", branch],
            git_c + ["add", "-A"],
            git_c + ["commit", "-m", "Publish from Agenthub workspace snapshot"],
        ):
            code, out, err = _run(cmd, cwd=staging, env=env, timeout=30)
            if code != 0:
                with connect() as conn:
                    _set_state(conn, row["request_id"], "failed", {**result, "reason": "git_commit_failed", "detail": (err or out)[:400]})
                return {"ok": False, "reason": "git"}
        origin = f"https://github.com/{owner}/{repo}.git"
        _run(git_c + ["remote", "add", "origin", origin], cwd=staging, env=env, timeout=15)
        code, out, err = _run(push_c + ["push", "-u", "origin", f"HEAD:refs/heads/{branch}"], cwd=staging, env=env, timeout=90)
        if code != 0:
            with connect() as conn:
                _set_state(conn, row["request_id"], "failed", {**result, "reason": "push_failed", "detail": (err or out)[:400]})
            return {"ok": False, "reason": "push"}
        code, out, err = _run([gh_bin(), "api", f"repos/{owner}/{repo}/commits/{branch}"], cwd=None, env=env, timeout=30)
        sha = ""
        if code == 0:
            try:
                sha = json.loads(out).get("sha") or ""
            except Exception:
                sha = ""
        result.update({"commit_sha": sha, "branch": branch, "pushed": True})
        with connect() as conn:
            _set_state(conn, row["request_id"], "succeeded", result)
            audit(conn, "publisher", "publish.push", row["request_id"], "", result.get("html_url") or "ok")
        return {"ok": True, "result": {k: result[k] for k in result if k != "token"}}
    finally:
        if staging and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        cfg_dir = secrets_dir() / "gh-config"
        if cfg_dir.is_dir():
            for p in cfg_dir.rglob("*"):
                if p.is_file():
                    try:
                        p.write_text("", encoding="utf-8")
                        p.unlink()
                    except Exception:
                        pass


def process_queue() -> dict[str, Any]:
    if not publisher_enabled():
        return {"skipped": True, "reason": "disabled"}
    if not load_github_token():
        return {"skipped": True, "reason": "no_token"}
    done = []
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM publish_requests WHERE state IN ('approved','creating_repo','pushing') ORDER BY created_at LIMIT 3"
        ).fetchall()
        items = [dict(r) for r in rows]
    for row in items:
        done.append({"request_id": row["request_id"], **execute_one(row)})
    return {"advanced": len(done), "items": done}
