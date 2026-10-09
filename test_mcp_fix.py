#!/usr/bin/env python3
"""MCP revision, idempotency, and staging entry. Never prints secrets."""
from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-mcpfix-")
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


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class McpFixTests(unittest.TestCase):
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
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-mcpfix"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": ["hub-shared"], "scopes": ["chat:write", "workspace:write:own"]},
        )

    def _p(self):
        return hub.principal_from_token(self.tok_a)

    def test_01_read_specific_revision(self):
        p = self._p()
        created = mcptools.workspace_write_text(p, relative_path="connection-tests.md", text="v1-body")
        self.assertEqual(created["revision"], 1)
        updated = mcptools.workspace_write_text(
            p, relative_path="connection-tests.md", text="v2-body", expected_revision=1
        )
        self.assertEqual(updated["revision"], 2)
        old = mcptools.workspace_read(p, file_id=created["file_id"], revision=1)
        self.assertEqual(old["revision"], 1)
        self.assertEqual(old["text"], "v1-body")
        self.assertEqual(old["current_revision"], 2)
        head = mcptools.workspace_read(p, file_id=created["file_id"], revision=0)
        self.assertEqual(head["revision"], 2)
        self.assertEqual(head["text"], "v2-body")
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.workspace_read(p, file_id=created["file_id"], revision=999999)
        self.assertEqual(ctx.exception.code, "revision_not_found")
        self.assertEqual(ctx.exception.details.get("current_revision"), 2)
        self.assertIn("REVISION_NOT_FOUND", ctx.exception.as_text())

    def test_02_idempotency_conflict(self):
        p = self._p()
        first = mcptools.workspace_write_text(
            p, relative_path="idem.md", text="alpha", idempotency_key="same-key"
        )
        again = mcptools.workspace_write_text(
            p, relative_path="idem.md", text="alpha", idempotency_key="same-key"
        )
        self.assertEqual(first["file_id"], again["file_id"])
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.workspace_write_text(
                p, relative_path="idem.md", text="beta", expected_revision=first["revision"], idempotency_key="same-key"
            )
        self.assertEqual(ctx.exception.code, "idempotency_conflict")
        got = mcptools.workspace_read(p, file_id=first["file_id"])
        self.assertEqual(got["text"], "alpha")

    def test_03_stage_file_returns_staging_id(self):
        p = self._p()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("pack/a.txt", b"hello-stage")
        data = buf.getvalue()
        staged = mcptools.binary_stage(
            p,
            name="tiny.zip",
            content_b64=base64.b64encode(data).decode("ascii"),
        )
        self.assertTrue(staged["staging_id"].startswith("up_"))
        self.assertEqual(staged["state"], "ready")
        preview = mcptools.import_prepare(p, staging_id=staged["staging_id"], dest="staged")
        self.assertEqual(preview["file_count"], 1)
        job = mcptools.import_commit(p, preview_id=preview["preview_id"], manifest_hash=preview["manifest_hash"])
        self.assertEqual(job["state"], "succeeded")

    def test_04_mcp_copy_not_readonly(self):
        p = self._p()
        surface = mcptools.mcp_surface(p)
        self.assertEqual(surface["mcp"], "restricted")
        self.assertIn("workspace_write_own", surface["mcp_writes"])
        self.assertIn("binary_upload", surface["mcp_writes"])
        listed = hub.workspaces_for(p)
        self.assertEqual(listed["mcp"], "restricted")
        self.assertEqual(hub.APP_VERSION, APP_VERSION)
        self.assertEqual(APP_VERSION, "1.4.5")

    def test_05_revision_conflict_code(self):
        p = self._p()
        created = mcptools.workspace_write_text(p, relative_path="rev.md", text="one")
        mcptools.workspace_write_text(p, relative_path="rev.md", text="two", expected_revision=created["revision"])
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.workspace_write_text(p, relative_path="rev.md", text="three", expected_revision=created["revision"])
        self.assertEqual(ctx.exception.code, "revision_conflict")
        self.assertEqual(ctx.exception.details.get("current_revision"), 2)
        self.assertIn("REVISION_CONFLICT", ctx.exception.as_text())

    def test_06_markdown_mime_from_extension(self):
        p = self._p()
        created = mcptools.workspace_write_text(p, relative_path="notes.md", text="# hello")
        self.assertTrue((created.get("mime_type") or "").startswith("text/markdown"))
        got = mcptools.workspace_read(p, file_id=created["file_id"])
        self.assertTrue((got.get("mime_type") or "").startswith("text/markdown"))
        plain = mcptools.workspace_write_text(p, relative_path="notes.txt", text="plain")
        self.assertTrue((plain.get("mime_type") or "").startswith("text/plain"))

    def test_07_path_traversal_not_archive_copy(self):
        p = self._p()
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.workspace_write_text(p, relative_path="../escape.md", text="nope")
        text = ctx.exception.as_text().lower()
        self.assertIn("path traversal", text)
        self.assertNotIn("archive", text)

    def test_08_write_envelope_schema_matches_app(self):
        r = self.client.post(
            "/api/v1/workspaces/me/nodes",
            headers=auth(self.tok_a),
            json={"name": "schema-check.md", "kind": "file", "body": "# x"},
        )
        self.assertEqual(r.status_code, 201, r.text[:400])
        body = r.json()
        self.assertEqual(body["schema_version"], APP_VERSION)
        got = mcptools.workspace_read(self._p(), file_id=body["data"]["node_id"])
        self.assertTrue((got.get("mime_type") or "").startswith("text/markdown"))

    def test_09_host_file_slot_stages_zip(self):
        p = self._p()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("pack/a.txt", b"from-file-slot")
        data = buf.getvalue()
        staged = mcptools.binary_stage(
            p,
            name="slot.zip",
            file={"name": "slot.zip", "data": base64.b64encode(data).decode("ascii"), "type": "application/zip"},
        )
        self.assertEqual(staged["state"], "ready")
        self.assertTrue(staged["staging_id"].startswith("up_"))
        preview = mcptools.import_prepare(p, staging_id=staged["staging_id"], dest="from-slot")
        self.assertEqual(preview["file_count"], 1)

    def test_10_host_file_rejects_arbitrary_url_and_paths(self):
        p = self._p()
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.binary_stage(p, name="nope.zip", file={"download_url": "https://example.com/secret.zip"})
        self.assertIn("not allowed", ctx.exception.as_text().lower())
        with self.assertRaises(mcptools.ToolFail) as ctx:
            mcptools.binary_stage(p, name="nope.zip", file="/mnt/data/Mahler.zip")
        self.assertIn("not readable", ctx.exception.as_text().lower())
        self.assertTrue(mcptools.file_host_ok("files.oaiusercontent.com"))
        self.assertFalse(mcptools.file_host_ok("example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
