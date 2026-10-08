#!/usr/bin/env python3
"""Plugin binary import: ticketed PUT + ZIP extract. Never prints secrets."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-binary-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1 import mcptools  # noqa: E402
from hubv1.store import refresh_paths  # noqa: E402
from hubv1.version import APP_VERSION  # noqa: E402

MAHLER_BYTES = 8_479_272
MAHLER_FILES = 84


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_pack(target: int = MAHLER_BYTES, nfiles: int = MAHLER_FILES) -> bytes:
    def build(payload: int, comment: bytes = b"") -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for i in range(nfiles - 1):
                zf.writestr(f"mahler/f{i:02d}.txt", b"x")
            zf.writestr("mahler/payload.bin", b"M" * payload)
            zf.comment = comment
        return buf.getvalue()

    lo, hi = 1, target
    best = (1, build(1))
    while lo <= hi:
        mid = (lo + hi) // 2
        data = build(mid)
        if len(data) <= target:
            best = (mid, data)
            lo = mid + 1
        else:
            hi = mid - 1
    payload, data = best
    need = target - len(data)
    if need:
        data = build(payload, b"P" * need)
    if len(data) != target:
        raise RuntimeError(f"zip size {len(data)} != {target}")
    return data


def make_traversal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("ok.txt", b"ok")
        info = zipfile.ZipInfo("../escape.txt")
        zf.writestr(info, b"nope")
    return buf.getvalue()


class BinaryBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        refresh_paths()
        hub.ensure_session_secret()
        hub.init_db()
        hub.bootstrap_admin()
        cls.admin = os.environ["AGENTHUB_API_TOKEN"]
        cls.tok_a = "token-agent-a-aaaaaaaa"
        cls.tok_b = "token-agent-b-bbbbbbbb"
        cls.tok_r = "token-agent-r-rrrrrrrr"
        for aid, tok in (("agent_a", cls.tok_a), ("agent_b", cls.tok_b), ("agent_r", cls.tok_r)):
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
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-bin"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write", "workspace:write:own"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-bin"},
            json={"agent_id": "agent_b", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write", "workspace:write:own"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-r-bin"},
            json={"agent_id": "agent_r", "roles": ["view"], "project_ids": [], "scopes": ["chat:write"]},
        )
        cls.zip_bytes = make_pack()

    def _p(self, token: str):
        return hub.principal_from_token(token)

    def test_01_version_and_mcp_fields_align(self):
        p = self._p(self.tok_a)
        status = hub.hub_status_for(p)
        caps = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        listed = hub.workspaces_for(p)
        self.assertEqual(status["version"], APP_VERSION)
        self.assertEqual(status["api_version"], APP_VERSION)
        self.assertEqual(caps["api_version"], APP_VERSION)
        self.assertEqual(hub.APP_VERSION, caps["api_version"])
        self.assertEqual(listed["mcp"], "restricted")
        self.assertIn("workspace_write_own", listed["mcp_writes"])

    def test_02_capabilities_binary_flag(self):
        caps_a = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        caps_r = self.client.get("/api/v1/capabilities", headers=auth(self.tok_r)).json()["data"]
        self.assertTrue(caps_a["features"]["binary_upload"])
        self.assertFalse(caps_r["features"]["binary_upload"])
        ctx = mcptools.hub_get_context(self._p(self.tok_a))
        self.assertTrue(ctx["capabilities"]["binary_upload"])

    def test_03_mahler_sized_zip_roundtrip(self):
        data = self.zip_bytes
        self.assertEqual(len(data), MAHLER_BYTES)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
        self.assertEqual(len(names), MAHLER_FILES)
        p = self._p(self.tok_a)
        begin = mcptools.binary_begin(p, name="Mahler.zip", bytes=len(data), sha256=sha(data))
        self.assertTrue(begin["staging_id"].startswith("up_"))
        self.assertTrue(begin["upload_ticket"].startswith("oht_"))
        unused_me = self.client.get("/api/v1/me", headers={"Authorization": f"Bearer {begin['upload_ticket']}"})
        self.assertEqual(unused_me.status_code, 403)
        put = self.client.put(
            f"/api/v1/uploads/{begin['staging_id']}/content",
            headers={"Authorization": f"Bearer {begin['upload_ticket']}", "Content-Type": "application/octet-stream"},
            content=data,
        )
        self.assertEqual(put.status_code, 200, put.text[:400])
        self.assertEqual(put.json()["data"]["sha256"], sha(data))
        blocked = self.client.get("/api/v1/me", headers={"Authorization": f"Bearer {begin['upload_ticket']}"})
        self.assertIn(blocked.status_code, (401, 403))
        reused = self.client.put(
            f"/api/v1/uploads/{begin['staging_id']}/content",
            headers={"Authorization": f"Bearer {begin['upload_ticket']}"},
            content=data,
        )
        self.assertIn(reused.status_code, (401, 403))
        st = mcptools.binary_status(p, staging_id=begin["staging_id"])
        self.assertEqual(st["state"], "ready")
        preview = mcptools.import_prepare(p, staging_id=begin["staging_id"], dest="Mahler")
        self.assertEqual(preview["file_count"], MAHLER_FILES)
        job = mcptools.import_commit(p, preview_id=preview["preview_id"], manifest_hash=preview["manifest_hash"], idempotency_key="mahler-1")
        self.assertEqual(job["state"], "succeeded")
        again = mcptools.import_commit(p, preview_id=preview["preview_id"], manifest_hash=preview["manifest_hash"], idempotency_key="mahler-1")
        self.assertEqual(again["job_id"], job["job_id"])
        listed = mcptools.workspace_list(p)
        paths = [it["path"] for it in listed["items"]]
        self.assertTrue(any(x.startswith("Mahler/") for x in paths))

    def test_04_optional_sha256_and_oauth_put(self):
        blob = b"tiny-zip-placeholder"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("pack/a.txt", b"hello")
        data = buf.getvalue()
        p = self._p(self.tok_a)
        begin = mcptools.binary_begin(p, name="tiny.zip", bytes=len(data), sha256="")
        put = self.client.put(
            f"/api/v1/uploads/{begin['staging_id']}/content",
            headers=auth(self.tok_a),
            content=data,
        )
        self.assertEqual(put.status_code, 200, put.text[:300])
        self.assertEqual(put.json()["data"]["sha256"], sha(data))
        preview = mcptools.import_prepare(p, staging_id=begin["staging_id"])
        self.assertEqual(preview["file_count"], 1)
        mcptools.import_commit(p, preview_id=preview["preview_id"], manifest_hash=preview["manifest_hash"])

    def test_05_traversal_rejected_and_cross_owner(self):
        data = make_traversal_zip()
        p = self._p(self.tok_a)
        begin = mcptools.binary_begin(p, name="bad.zip", bytes=len(data), sha256=sha(data))
        put = self.client.put(
            f"/api/v1/uploads/{begin['staging_id']}/content",
            headers=auth(self.tok_a),
            content=data,
        )
        self.assertEqual(put.status_code, 200)
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.import_prepare(p, staging_id=begin["staging_id"], dest="bad")
        self.assertIn(ctx.exception.code, {"invalid", "too_large"})
        with self.assertRaises(mcptools.ToolFail):
            mcptools.binary_status(self._p(self.tok_b), staging_id=begin["staging_id"])
        with self.assertRaises(mcptools.ToolFail):
            mcptools.binary_begin(self._p(self.tok_r), name="nope.zip", bytes=4)

    def test_06_read_only_cannot_create_upload(self):
        r = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_r),
            json={"name": "x.zip", "bytes": 4, "sha256": "0" * 64, "purpose": "archive"},
        )
        self.assertIn(r.status_code, (403, 422))


if __name__ == "__main__":
    unittest.main(verbosity=2)
