#!/usr/bin/env python3
"""Identity token lookup, fail cache, and trusted-proxy client IP."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

TMP = tempfile.mkdtemp(prefix="agenthub-auth-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

import app as hub  # noqa: E402
from hubv1.store import refresh_paths  # noqa: E402


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        refresh_paths()
        hub.ensure_session_secret()
        hub.init_db()
        hub.bootstrap_admin()
        hub._token_cache.clear()
        hub._token_fail.clear()

    def setUp(self):
        hub._token_cache.clear()
        hub._token_fail.clear()

    def test_prefixed_token_looks_up_by_id(self):
        token = hub.mint_identity_token()
        tid = hub.identity_token_id(token)
        self.assertTrue(tid)
        salt, digest = hub.new_token_parts(token)
        with hub.db() as conn:
            conn.execute(
                "INSERT INTO identities(id, kind, public_alias, token_salt, token_hash, token_id, roles, expires_at, revoked_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    "agent_pref",
                    "agent",
                    "agent_pref",
                    salt,
                    digest,
                    tid,
                    json.dumps(["view", "report"]),
                    None,
                    None,
                    hub.utcnow_iso(),
                ),
            )
        p = hub.principal_from_token(token)
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "agent_pref")
        self.assertIsNone(hub.principal_from_token(hub.mint_identity_token()))

    def test_unknown_prefixed_token_skips_scan(self):
        token = hub.mint_identity_token()
        calls = []
        orig = hub.hash_token

        def wrapped(*args, **kwargs):
            calls.append(1)
            return orig(*args, **kwargs)

        hub.hash_token = wrapped
        try:
            self.assertIsNone(hub.principal_from_token(token))
            self.assertEqual(calls, [])
            self.assertIsNone(hub.principal_from_token(token))
            self.assertEqual(calls, [])
        finally:
            hub.hash_token = orig

    def test_legacy_fail_is_cached(self):
        calls = []
        orig = hub.hash_token

        def wrapped(*args, **kwargs):
            calls.append(1)
            return orig(*args, **kwargs)

        hub.hash_token = wrapped
        try:
            bad = "not-a-real-legacy-token-xxxx"
            self.assertIsNone(hub.principal_from_token(bad))
            n = len(calls)
            self.assertGreater(n, 0)
            self.assertIsNone(hub.principal_from_token(bad))
            self.assertEqual(len(calls), n)
        finally:
            hub.hash_token = orig

    def test_xff_only_from_trusted_proxy(self):
        foreign = SimpleNamespace(
            headers={"x-forwarded-for": "203.0.113.9", "cf-connecting-ip": ""},
            client=SimpleNamespace(host="8.8.8.8"),
        )
        self.assertEqual(hub.client_ip(foreign), "8.8.8.8")
        local = SimpleNamespace(
            headers={"x-forwarded-for": "203.0.113.9"},
            client=SimpleNamespace(host="127.0.0.1"),
        )
        self.assertEqual(hub.client_ip(local), "203.0.113.9")


if __name__ == "__main__":
    unittest.main(verbosity=2)
