#!/usr/bin/env python3
"""Allowlisted GitHub read proxy. Never prints tokens or hits live GitHub."""
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-ghread-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1 import github_read  # noqa: E402
from hubv1 import mcptools  # noqa: E402
from hubv1.store import connect, refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _fake(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    blob = json.dumps(headers).lower()
    if "gho_" in blob or "ghp_" in blob or "github_pat_" in blob:
        raise AssertionError("token leaked into mock headers dump path")
    if url.endswith("/users/sunnyspot114514/repos?type=owner&per_page=40&sort=updated") or "/users/sunnyspot114514/repos" in url:
        body = [
            {
                "name": "agenthub",
                "private": False,
                "description": "hub ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "default_branch": "main",
                "html_url": "https://github.com/sunnyspot114514/agenthub",
                "updated_at": "2026-10-10T00:00:00Z",
                "owner": {"login": "sunnyspot114514"},
            }
        ]
        return 200, json.dumps(body).encode()
    if "/git/trees/" in url:
        body = {
            "truncated": False,
            "tree": [
                {"path": "README.md", "type": "blob", "size": 12, "sha": "a" * 40},
                {"path": "src/app.py", "type": "blob", "size": 20, "sha": "b" * 40},
            ],
        }
        return 200, json.dumps(body).encode()
    if "/contents/" in url:
        raw = base64.b64encode(b"# hello\n").decode("ascii")
        body = {
            "type": "file",
            "size": 8,
            "encoding": "base64",
            "content": raw,
            "html_url": "https://github.com/sunnyspot114514/agenthub/blob/main/README.md",
            "sha": "c" * 40,
        }
        return 200, json.dumps(body).encode()
    if url.rstrip("/").endswith("/repos/sunnyspot114514/agenthub"):
        return 200, json.dumps({"default_branch": "main"}).encode()
    return 404, b"{}"


class GitHubReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        refresh_paths()
        hub.ensure_session_secret()
        hub.init_db()
        hub.bootstrap_admin()
        cls.admin = os.environ["AGENTHUB_API_TOKEN"]
        cls.tok_a = "token-agent-a-aaaaaaaa"
        salt, digest = hub.new_token_parts(cls.tok_a)
        with hub.db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identities(id, kind, public_alias, token_salt, token_hash, roles, expires_at, revoked_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("agent_a", "agent", "agent_a", salt, digest, json.dumps(["view", "report"]), None, None, hub.utcnow_iso()),
            )
        hub._token_cache.clear()
        with connect() as conn:
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('feature_github_read','1')")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('publisher_allowed_owners','[\"sunnyspot114514\"]')")
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-gh"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write", "workspace:write:own"]},
        )

    def setUp(self):
        github_read.set_transport(_fake)

    def tearDown(self):
        github_read.set_transport(None)

    def test_01_list_allowlisted_and_redact(self):
        p = hub.principal_from_token(self.tok_a)
        listed = mcptools.github_list_repos(p)
        self.assertEqual(listed["items"][0]["repo"], "sunnyspot114514/agenthub")
        self.assertNotIn("ghp_", json.dumps(listed))
        self.assertIn("[redacted]", listed["items"][0]["description"])

    def test_02_other_owner_forbidden(self):
        p = hub.principal_from_token(self.tok_a)
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.github_list_files(p, repo="openai/math")
        self.assertEqual(ctx.exception.code, "forbidden")

    def test_03_read_file_and_list(self):
        p = hub.principal_from_token(self.tok_a)
        files = mcptools.github_list_files(p, repo="sunnyspot114514/agenthub")
        self.assertEqual({i["path"] for i in files["items"]}, {"README.md", "src/app.py"})
        got = mcptools.github_read_file(p, repo="agenthub", path="README.md")
        self.assertIn("# hello", got["text"])
        self.assertFalse(got["binary"])

    def test_04_rest_requires_auth_and_capabilities(self):
        self.assertEqual(self.client.get("/api/v1/github/repos").status_code, 401)
        r = self.client.get("/api/v1/github/repos", headers=auth(self.tok_a))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertNotIn("ghp_", r.text)
        caps = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        self.assertTrue(caps["features"]["github_read"])
        self.assertIn("github_write", caps["cannot"])
        deny = self.client.get("/api/v1/github/files", headers=auth(self.tok_a), params={"repo": "octocat/Hello-World"})
        self.assertEqual(deny.status_code, 403)

    def test_05_path_traversal(self):
        p = hub.principal_from_token(self.tok_a)
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.github_read_file(p, repo="sunnyspot114514/agenthub", path="../secrets")
        self.assertEqual(ctx.exception.code, "invalid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
