#!/usr/bin/env python3
"""Publisher request ACL tests. Does not call GitHub."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-pub-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1.store import connect, refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class PublishTests(unittest.TestCase):
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
        with connect() as conn:
            conn.execute("UPDATE hub_config SET value='1' WHERE key='feature_publisher'")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('mit_copyright_holder','sunnyspot114514')")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('publisher_allowed_owners','[\"sunnyspot114514\"]')")
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-pub"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own", "publish:request"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-pub"},
            json={"agent_id": "agent_b", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own"]},
        )

    def json(self, method, url, token, data=None, expected=None):
        r = self.client.request(method, url, headers=auth(token), json=data)
        if expected is not None:
            self.assertEqual(r.status_code, expected, f"{method} {url} {r.status_code} {r.text[:400]}")
        return r

    def test_01_agent_b_cannot_request(self):
        r = self.json("POST", "/api/v1/publish-requests", self.tok_b, {"node_ids": ["x"], "target_owner": "sunnyspot114514", "repo": "demo", "create_repo": True})
        self.assertEqual(r.status_code, 403)

    def test_02_request_and_agent_cannot_approve(self):
        created = self.json("POST", "/api/v1/workspaces/me/nodes", self.tok_a, {"name": "readme.md", "kind": "file", "body": "# demo"}, expected=201).json()["data"]
        req = self.json(
            "POST",
            "/api/v1/publish-requests",
            self.tok_a,
            {"node_ids": [created["node_id"]], "target_owner": "sunnyspot114514", "repo": "agenthub-demo-pub", "create_repo": True, "branch": "main"},
            expected=201,
        ).json()["data"]
        rid = req["request_id"]
        self.assertEqual(req["state"], "awaiting_approval")
        r = self.json("POST", f"/api/v1/publish-requests/{rid}/approve", self.tok_a)
        self.assertEqual(r.status_code, 403)
        r = self.json("POST", "/api/v1/publish-requests", self.tok_a, {"node_ids": [created["node_id"]], "target_owner": "someoneelse", "repo": "nope", "create_repo": True})
        self.assertEqual(r.status_code, 403)

    def test_03_console_submit_and_zip_publish(self):
        html = self.client.get("/console/publish", headers=auth(self.tok_a))
        self.assertEqual(html.status_code, 200)
        self.assertIn("提交建仓发布申请", html.text)
        self.assertIn("sunnyspot114514", html.text)
        import io
        import tarfile

        buf = io.BytesIO()
        payload = b"# bundle\n"
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name="readme.md")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        up = self.client.post(
            "/api/v1/workspaces/me/uploads",
            headers=auth(self.tok_a),
            files={"file": ("bundle.tar", buf.getvalue(), "application/x-tar")},
        )
        self.assertEqual(up.status_code, 201, up.text[:400])
        self.assertTrue(up.json()["data"].get("extracted"))
        folder = up.json()["data"]["node_id"]
        me = self.json("GET", "/api/v1/workspaces/me", self.tok_a, expected=200).json()["data"]
        kids = self.client.get(
            f"/api/v1/workspaces/{me['workspace_id']}/nodes",
            headers=auth(self.tok_a),
            params={"parent_id": folder},
        )
        self.assertEqual(kids.status_code, 200, kids.text[:400])
        files = [n for n in kids.json()["data"]["items"] if n["kind"] == "file"]
        self.assertTrue(files)
        nid = files[0]["node_id"]
        form = self.client.post(
            "/console/publish/requests",
            headers=auth(self.tok_a),
            data={"node_ids": nid, "target_owner": "sunnyspot114514", "repo": "agenthub-tar-demo", "branch": "main", "create_repo": "1"},
            follow_redirects=False,
        )
        self.assertEqual(form.status_code, 303, form.text[:400])
        listed = self.json("GET", "/api/v1/publish-requests", self.tok_a, expected=200).json()["data"]
        names = [i.get("repo") for i in listed["items"]]
        self.assertIn("agenthub-tar-demo", names)

    def test_04_empty_publish_is_403_without_scope(self):
        r = self.client.post("/api/v1/publish-requests", headers=auth(self.tok_b), json={})
        self.assertEqual(r.status_code, 403, r.text[:300])
        r = self.client.post("/api/v1/publish/plans", headers=auth(self.tok_b), json={})
        self.assertEqual(r.status_code, 403, r.text[:300])

    def test_05_heartbeat_ok_is_boolean(self):
        r = self.client.post("/v1/agents/me/heartbeat", headers=auth(self.tok_a), json={"status": "idle"})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIs(r.json()["ok"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
