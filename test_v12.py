#!/usr/bin/env python3
"""Agenthub 1.2 workspace tests. Never prints secrets."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-v12-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1.store import refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class V12Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        refresh_paths()
        hub.ensure_session_secret()
        hub.init_db()
        hub.bootstrap_admin()
        cls.admin = os.environ["AGENTHUB_API_TOKEN"]
        cls.tok_a = "token-agent-a-aaaaaaaa"
        cls.tok_b = "token-agent-b-bbbbbbbb"
        for aid, tok in (("agent_a", cls.tok_a), ("agent_b", cls.tok_b)):
            salt, digest = hub.new_token_parts(tok)
            with hub.db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO identities(id, kind, public_alias, token_salt, token_hash, roles, expires_at, revoked_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (aid, "agent", aid, salt, digest, json.dumps(["view", "report"]), None, None, hub.utcnow_iso()),
                )
        hub._token_cache.clear()
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-ws"},
            json={
                "agent_id": "agent_a",
                "roles": ["view", "report"],
                "project_ids": ["hub-shared"],
                "scopes": ["chat:write", "workspace:write:own"],
            },
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-ws"},
            json={
                "agent_id": "agent_b",
                "roles": ["view", "report"],
                "project_ids": ["hub-shared"],
                "scopes": ["chat:write"],
            },
        )

    def json(self, method, url, token, data=None, expected=None, key=None):
        headers = auth(token)
        if key:
            headers["Idempotency-Key"] = key
        r = self.client.request(method.upper(), url, headers=headers, json=data) if data is not None else self.client.request(method.upper(), url, headers=headers)
        if expected is not None:
            self.assertEqual(r.status_code, expected, f"{method} {url} {r.status_code} {r.text[:400]}")
        return r

    def test_01_unique_workspace_and_retry(self):
        a1 = self.json("GET", "/api/v1/workspaces/me", self.tok_a, expected=200).json()["data"]
        a2 = self.json("GET", "/api/v1/workspaces/me", self.tok_a, expected=200).json()["data"]
        self.assertEqual(a1["workspace_id"], a2["workspace_id"])
        self.assertEqual(a1["owner_agent_id"], "agent_a")
        self.assertTrue(a1["writable"])
        b = self.json("GET", "/api/v1/workspaces/me", self.tok_b, expected=200).json()["data"]
        self.assertNotEqual(a1["workspace_id"], b["workspace_id"])
        self.assertFalse(b["writable"])
        listing = self.json("GET", "/api/v1/workspaces", self.tok_b, expected=200).json()["data"]["items"]
        self.assertTrue(any(i["owner_agent_id"] == "agent_a" for i in listing))

    def test_02_cross_owner_read_not_write(self):
        created = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "notes.md", "kind": "file", "body": "hello-a"},
            expected=201,
        ).json()["data"]
        nid = created["node_id"]
        got = self.json("GET", f"/api/v1/nodes/{nid}", self.tok_b, expected=200).json()["data"]
        self.assertEqual(got["name"], "notes.md")
        self.assertFalse(got["writable"])
        dl = self.client.get(f"/api/v1/nodes/{nid}/file", headers=auth(self.tok_b))
        self.assertEqual(dl.status_code, 200)
        self.assertIn(b"hello-a", dl.content)
        anon = self.client.get(f"/api/v1/nodes/{nid}/file")
        self.assertEqual(anon.status_code, 401)
        r = self.json(
            "PUT",
            f"/api/v1/nodes/{nid}",
            self.tok_b,
            {"expected_revision": created["revision"], "body": "hijack"},
        )
        self.assertEqual(r.status_code, 403)
        r = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_b,
            {"name": "x.md", "kind": "file", "body": "no", "workspace_id": created.get("workspace_id")},
        )
        self.assertEqual(r.status_code, 403)

    def test_03_spoof_and_paths(self):
        r = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "ok.md", "kind": "file", "body": "x", "author": "agent_b"},
        )
        self.assertEqual(r.status_code, 403)
        r = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "../etc/passwd", "kind": "file", "body": "x"},
        )
        self.assertEqual(r.status_code, 400)
        r = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "a/b.md", "kind": "file", "body": "x"},
        )
        self.assertEqual(r.status_code, 400)

    def test_04_revision_conflict_and_restore(self):
        created = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "rev.md", "kind": "file", "body": "v1"},
            expected=201,
        ).json()["data"]
        nid = created["node_id"]
        self.json(
            "PUT",
            f"/api/v1/nodes/{nid}",
            self.tok_a,
            {"expected_revision": created["revision"], "body": "v2"},
            expected=200,
        )
        r = self.json(
            "PUT",
            f"/api/v1/nodes/{nid}",
            self.tok_a,
            {"expected_revision": created["revision"], "body": "stale"},
        )
        self.assertEqual(r.status_code, 409)
        cur = self.json("GET", f"/api/v1/nodes/{nid}", self.tok_a, expected=200).json()["data"]
        gone = self.json(
            "DELETE",
            f"/api/v1/nodes/{nid}",
            self.tok_a,
            {"expected_revision": cur["revision"]},
            expected=200,
        ).json()["data"]
        self.json(
            "POST",
            f"/api/v1/nodes/{nid}/restore",
            self.tok_a,
            {"expected_revision": gone["revision"]},
            expected=200,
        )

    def test_05_old_scopes_not_enough_and_publisher_off(self):
        acc = self.json("GET", "/api/v1/capabilities", self.tok_b, expected=200).json()["data"]
        self.assertFalse(acc["workspace_write_own"])
        self.assertFalse(acc["feature_publisher"])
        self.assertIn("shell", acc["cannot"])
        self.assertFalse(acc["agent_wake"])
        r = self.json(
            "POST",
            "/api/v1/publish-requests",
            self.tok_a,
            {"node_ids": ["n1"], "target_owner": "x", "repo": "y"},
        )
        self.assertEqual(r.status_code, 403)
        r = self.json(
            "POST",
            "/api/v1/worklogs",
            self.tok_a,
            {"project_id": "hub-shared", "done": "should fail"},
            key="wl-no",
        )
        self.assertEqual(r.status_code, 403)

    def test_06_personal_worklog_own_only(self):
        me = self.json("GET", "/api/v1/workspaces/me", self.tok_a, expected=200).json()["data"]
        r = self.json(
            "POST",
            "/api/v1/worklogs",
            self.tok_a,
            {"workspace_id": me["workspace_id"], "done": "写了笔记"},
            key="wl-own",
        )
        self.assertIn(r.status_code, (200, 201), r.text[:400])
        other = self.json("GET", "/api/v1/workspaces/me", self.tok_b, expected=200).json()["data"]
        r = self.json(
            "POST",
            "/api/v1/worklogs",
            self.tok_b,
            {"workspace_id": other["workspace_id"], "done": "b cannot"},
            key="wl-b",
        )
        self.assertEqual(r.status_code, 403)

    def test_07_context_budget_lists_workspaces(self):
        ctx = self.json("GET", "/api/v1/context", self.tok_a, expected=200).json()["data"]
        self.assertIn("capabilities", ctx)
        self.assertIn("my_workspace", ctx)
        self.assertFalse(ctx["capabilities"]["agent_wake"])
        self.assertNotIn("token-agent-a", json.dumps(ctx))

    def test_08_zip_upload_and_exe_rejected(self):
        import io
        import zipfile

        from hubv1.flags import flag_int

        self.assertEqual(flag_int("workspace_max_file_bytes"), 200 * 1024 * 1024)
        me = self.json("GET", "/api/v1/workspaces/me", self.tok_a, expected=200).json()["data"]
        self.assertEqual(int(me["quota_bytes"]), 50 * 1024 * 1024 * 1024)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.md", "# hi\n")
            zf.writestr("src/a.txt", "hello")
        r = self.client.post(
            "/api/v1/workspaces/me/uploads",
            headers=auth(self.tok_a),
            files={"file": ("pack.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r.status_code, 201, r.text[:400])
        data = r.json()["data"]
        self.assertTrue(data.get("extracted"))
        self.assertEqual(data["file_count"], 2)
        self.assertEqual(data["name"], "pack")
        slip = io.BytesIO()
        with zipfile.ZipFile(slip, "w") as zf:
            zf.writestr("../x.txt", "nope")
        r = self.client.post(
            "/api/v1/workspaces/me/uploads",
            headers=auth(self.tok_a),
            files={"file": ("slip.zip", slip.getvalue(), "application/zip")},
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            "/api/v1/workspaces/me/uploads",
            headers=auth(self.tok_b),
            files={"file": ("other.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r.status_code, 403)
        r = self.client.post(
            "/api/v1/workspaces/me/uploads",
            headers=auth(self.tok_a),
            files={"file": ("evil.exe", b"MZ", "application/octet-stream")},
        )
        self.assertEqual(r.status_code, 400)
        html = self.client.get("/console/workspaces/me", headers=auth(self.tok_a))
        self.assertEqual(html.status_code, 200)
        self.assertIn("解压", html.text)
        self.assertIn("pack/hello.md", html.text)

    def test_09_put_keeps_previous_mime(self):
        created = self.json(
            "POST",
            "/api/v1/workspaces/me/nodes",
            self.tok_a,
            {"name": "keep.md", "kind": "file", "body": "# one", "mime_type": "text/markdown"},
            expected=201,
        ).json()["data"]
        nid = created["node_id"]
        self.json(
            "PUT",
            f"/api/v1/nodes/{nid}",
            self.tok_a,
            {"expected_revision": created["revision"], "body": "# two"},
            expected=200,
        )
        vers = self.json("GET", f"/api/v1/nodes/{nid}/versions", self.tok_a, expected=200).json()["data"]["items"]
        self.assertEqual(vers[-1]["mime_type"], "text/markdown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
