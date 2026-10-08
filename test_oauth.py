#!/usr/bin/env python3
"""OAuth 2.1 + restricted MCP contract tests. Never prints secrets."""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

TMP = tempfile.mkdtemp(prefix="agenthub-v16-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1 import mcptools  # noqa: E402
from hubv1.acl import access_for  # noqa: E402
from hubv1.oauth_store import pkce_s256  # noqa: E402
from hubv1.store import connect, refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    return verifier, pkce_s256(verifier)


class OAuthTests(unittest.TestCase):
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
        cls._cm = TestClient(hub.app, base_url="https://agenthub.example.test")
        cls.client = cls._cm.__enter__()
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-oauth"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write", "workspace:write:own"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-oauth"},
            json={"agent_id": "agent_b", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write"]},
        )

    @classmethod
    def tearDownClass(cls):
        cls._cm.__exit__(None, None, None)

    def _register(self) -> dict:
        r = self.client.post(
            "/oauth/register",
            json={"client_name": "test-host", "redirect_uris": ["http://127.0.0.1:9/cb"], "token_endpoint_auth_method": "none"},
        )
        self.assertEqual(r.status_code, 201, r.text[:300])
        return r.json()

    def _session(self, token: str) -> None:
        r = self.client.post("/session", data={"token": token}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text[:200])

    def _tokens(self, *, scopes="hub:read", token=None, client=None):
        token = token or self.tok_a
        client = client or self._register()
        verifier, challenge = pkce()
        resource = "https://agenthub.example.test/mcp/"
        self._session(token)
        r = self.client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": scopes,
                "resource": resource,
                "state": "st1",
            },
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertNotIn("7 天", r.text)
        self.assertNotIn("30 天", r.text)
        found = re.search(r'name="pending_id" value="([^"]+)"', r.text)
        self.assertIsNotNone(found, r.text[:400])
        pending = found.group(1)
        sid = self.client.cookies.get("agenthub_session") or ""
        body = urlencode([("pending_id", pending), ("decision", "allow")] + [("scope", s) for s in scopes.split()])
        r = self.client.post(
            "/oauth/authorize",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": f"agenthub_session={sid}; agenthub_oauth_pending={pending}",
            },
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302, r.text[:300])
        loc = r.headers["location"]
        qs = parse_qs(urlparse(loc).query)
        self.assertEqual(qs.get("iss", [""])[0], "https://agenthub.example.test")
        code = qs["code"][0]
        r = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": client["redirect_uris"][0],
                "client_id": client["client_id"],
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        self.assertEqual(r.status_code, 200, r.text[:400])
        body = r.json()
        self.assertTrue(body["access_token"].startswith("oha_"))
        self.assertTrue(body["refresh_token"].startswith("ohr_"))
        self.assertIsInstance(body["expires_in"], int)
        return body, client, verifier

    def test_a01_anonymous_mcp_401_challenge(self):
        r = self.client.get("/mcp/")
        self.assertEqual(r.status_code, 401)
        self.assertIn("resource_metadata", r.headers.get("www-authenticate", "").lower())
        self.assertNotIn("<html", r.text.lower())
        self.assertNotIn("identity", r.text.lower())

    def test_a02_metadata_fixed_https(self):
        as_meta = self.client.get("/.well-known/oauth-authorization-server").json()
        pr = self.client.get("/.well-known/oauth-protected-resource/mcp").json()
        self.assertEqual(as_meta["issuer"], "https://agenthub.example.test")
        self.assertEqual(pr["resource"], "https://agenthub.example.test/mcp/")
        self.assertIn("S256", as_meta["code_challenge_methods_supported"])
        self.assertTrue(as_meta["authorization_response_iss_parameter_supported"])
        self.assertIn("hub:read", pr["scopes_supported"])
        self.assertIn("workspace:write:own", pr["scopes_supported"])

    def test_a03_connect_and_me(self):
        tokens, _, _ = self._tokens()
        r = self.client.get("/api/v1/me", headers=auth(tokens["access_token"]))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(r.json()["data"]["identity_id"], "agent_a")

    def test_a04_bad_tokens(self):
        r = self.client.get("/mcp/", headers=auth("oha_notarealtokenvalue000000000000000000"))
        self.assertEqual(r.status_code, 401)
        r = self.client.get("/api/v1/me", headers=auth("oha_notarealtokenvalue000000000000000000"))
        self.assertEqual(r.status_code, 401)

    def test_a05_pkce_and_code_replay(self):
        client = self._register()
        verifier, challenge = pkce()
        self._session(self.tok_a)
        r = self.client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "hub:read",
                "resource": "https://agenthub.example.test/mcp/",
            },
        )
        found = re.search(r'name="pending_id" value="([^"]+)"', r.text)
        self.assertIsNotNone(found, r.text[:400])
        pending = found.group(1)
        sid = self.client.cookies.get("agenthub_session") or ""
        body = urlencode([("pending_id", pending), ("decision", "allow"), ("scope", "hub:read")])
        r = self.client.post(
            "/oauth/authorize",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": f"agenthub_session={sid}; agenthub_oauth_pending={pending}",
            },
            follow_redirects=False,
        )
        self.assertIn("location", r.headers, r.text[:300])
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        tok_body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client["redirect_uris"][0],
            "client_id": client["client_id"],
            "resource": "https://agenthub.example.test/mcp/",
        }
        bad = self.client.post("/oauth/token", data={**tok_body, "code_verifier": "x" * 43})
        self.assertEqual(bad.status_code, 400)
        burned = self.client.post("/oauth/token", data={**tok_body, "code_verifier": verifier})
        self.assertEqual(burned.status_code, 400)
        tokens, _, _ = self._tokens()
        replay = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": tokens["access_token"],
                "redirect_uri": client["redirect_uris"][0],
                "client_id": client["client_id"],
                "code_verifier": verifier,
                "resource": "https://agenthub.example.test/mcp/",
            },
        )
        self.assertEqual(replay.status_code, 400)

    def test_a06_redirect_not_allowlisted(self):
        client = self._register()
        verifier, challenge = pkce()
        r = self.client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": "https://evil.example/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "hub:read",
                "resource": "https://agenthub.example.test/mcp/",
            },
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 400)

    def test_a07_forged_pending_rejected(self):
        self._session(self.tok_a)
        r = self.client.post("/oauth/authorize", data={"pending_id": "pend_nope", "decision": "allow"}, follow_redirects=False)
        self.assertEqual(r.status_code, 400)

    def test_a08_dcr_private_redirect(self):
        r = self.client.post("/oauth/register", json={"redirect_uris": ["http://169.254.169.254/cb"]})
        self.assertEqual(r.status_code, 400)

    def test_a09_refresh(self):
        tokens, client, _ = self._tokens()
        r = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client["client_id"],
                "resource": "https://agenthub.example.test/mcp/",
            },
        )
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertNotEqual(r.json()["access_token"], tokens["access_token"])

    def test_a10_refresh_replay_revokes_family(self):
        tokens, client, _ = self._tokens()
        old = tokens["refresh_token"]
        first = self.client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": old, "client_id": client["client_id"], "resource": "https://agenthub.example.test/mcp/"},
        )
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": old, "client_id": client["client_id"], "resource": "https://agenthub.example.test/mcp/"},
        )
        self.assertEqual(second.status_code, 400)
        later = self.client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": first.json()["refresh_token"], "client_id": client["client_id"], "resource": "https://agenthub.example.test/mcp/"},
        )
        self.assertEqual(later.status_code, 400)
        r = self.client.get("/api/v1/me", headers=auth(first.json()["access_token"]))
        self.assertEqual(r.status_code, 401)

    def test_a11_revoke(self):
        tokens, client, _ = self._tokens()
        r = self.client.post("/oauth/revoke", data={"token": tokens["refresh_token"], "client_id": client["client_id"]})
        self.assertEqual(r.status_code, 200)
        r = self.client.get("/api/v1/me", headers=auth(tokens["access_token"]))
        self.assertEqual(r.status_code, 401)

    def test_a12_readonly_cannot_write(self):
        tokens, _, _ = self._tokens(scopes="hub:read")
        p = hub.principal_from_token(tokens["access_token"])
        with self.assertRaises(mcptools.ToolFail):
            mcptools.workspace_write_text(p, relative_path="x.md", text="nope")

    def test_a13_reconnect_same_identity(self):
        t1, c1, _ = self._tokens()
        t2, c2, _ = self._tokens()
        a = self.client.get("/api/v1/me", headers=auth(t1["access_token"])).json()["data"]["identity_id"]
        b = self.client.get("/api/v1/me", headers=auth(t2["access_token"])).json()["data"]["identity_id"]
        self.assertEqual(a, b)
        self.assertNotEqual(c1["client_id"], c2["client_id"])

    def test_b01_write_text_and_readback(self):
        tokens, _, _ = self._tokens(scopes="hub:read workspace:write:own")
        p = hub.principal_from_token(tokens["access_token"])
        info = mcptools.workspace_write_text(p, relative_path="oauth-test.md", text="hello-oauth", idempotency_key="k1")
        again = mcptools.workspace_write_text(p, relative_path="oauth-test.md", text="hello-oauth", idempotency_key="k1")
        self.assertEqual(info["file_id"], again["file_id"])
        got = mcptools.workspace_read(p, file_id=info["file_id"])
        self.assertEqual(got["text"], "hello-oauth")
        self.assertEqual(got["sha256"], info["sha256"])
        with self.assertRaises(mcptools.ToolFail):
            mcptools.workspace_write_text(p, relative_path="oauth-test.md", text="other", expected_revision=0)

    def test_b08_chat_idempotent(self):
        self.client.post(
            "/api/v1/threads",
            headers={**auth(self.tok_a), "Idempotency-Key": "th-oauth"},
            json={"kind": "project", "project_id": "hub-shared", "title": "hub"},
        )
        listed = self.client.get("/api/v1/threads", headers=auth(self.tok_a)).json()["data"]["items"]
        tid = listed[0]["thread_id"]
        tokens, _, _ = self._tokens(scopes="hub:read chat:write")
        p = hub.principal_from_token(tokens["access_token"])
        m1 = mcptools.chat_send(p, channel=tid, text="once", idempotency_key="chat-1")
        m2 = mcptools.chat_send(p, channel=tid, text="once", idempotency_key="chat-1")
        self.assertEqual(m1["message_id"], m2["message_id"])

    def test_b13_legacy_bearer_still_works(self):
        r = self.client.get("/api/v1/me", headers=auth(self.tok_a))
        self.assertEqual(r.status_code, 200)
        r = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["data"]["features"]["binary_upload"])

    def test_plugin_pack_has_no_secrets(self):
        root = Path(__file__).resolve().parent / "plugin" / "agenthub"
        blob = ""
        for p in root.rglob("*"):
            if p.is_file():
                blob += p.read_text(encoding="utf-8")
        for bad in ("oha_", "ohr_", "ghp_", "Authorization", "AGENTHUB_API_TOKEN"):
            self.assertNotIn(bad, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
