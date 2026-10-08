#!/usr/bin/env python3
"""Agenthub 1.3 / CLI contract tests (acceptance 01-24). Never prints secrets."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="agenthub-v14-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"
sys.path.insert(0, str(Path(__file__).resolve().parent / "agenthub-cli" / "src"))

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1.store import connect, refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class V14Tests(unittest.TestCase):
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
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('mit_copyright_holder','Xiwei Chen')")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('publisher_allowed_owners','[\"sunnyspot114514\"]')")
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-v14"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own", "publish:request"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-v14"},
            json={"agent_id": "agent_b", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own"]},
        )

    def me(self, token):
        r = self.client.get("/api/v1/me", headers=auth(token))
        self.assertEqual(r.status_code, 200, r.text[:400])
        return r.json()["data"]

    def upload(self, token, name: str, data: bytes, purpose="file"):
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(token),
            json={"name": name, "bytes": len(data), "sha256": sha(data), "purpose": purpose},
        )
        self.assertEqual(decl.status_code, 201, decl.text[:400])
        uid = decl.json()["data"]["upload_id"]
        put = self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(token), content=data)
        self.assertEqual(put.status_code, 200, put.text[:400])
        return uid

    def preview(self, token, uid, dest):
        me = self.me(token)
        return self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports/preview",
            headers=auth(token),
            json={"upload_id": uid, "dest": dest},
        )

    def test_01_help_entrypoint(self):
        import subprocess

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent / "agenthub-cli" / "src")
        r = subprocess.run([sys.executable, "-m", "agenthub_cli", "--help"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("workspace", r.stdout)
        r2 = subprocess.run([sys.executable, "-m", "agenthub_cli", "chat"], capture_output=True, text=True, env=env)
        self.assertEqual(r2.returncode, 10)

    def test_02_min_client_version_present(self):
        caps = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        self.assertEqual(caps["min_client_version"], "0.1.0")
        from hubv1.version import APP_VERSION

        self.assertEqual(caps["api_version"], APP_VERSION)
        self.assertIn("zip", caps["archives"])
        self.assertTrue(caps["features"]["atomic_import"])
        self.assertFalse(caps["features"]["resumable_upload"])

    def test_03_auth_errors_no_token_leak(self):
        r = self.client.get("/api/v1/me")
        self.assertEqual(r.status_code, 401)
        blob = r.text + json.dumps(r.json())
        self.assertNotIn(self.tok_a, blob)
        self.assertNotIn(self.admin, blob)
        r = self.client.get("/api/v1/me", headers=auth("nope-nope-nope-nope"))
        self.assertEqual(r.status_code, 401)

    def test_04_owner_isolation_and_no_approve(self):
        me = self.me(self.tok_a)
        other = self.me(self.tok_b)
        uid = self.upload(self.tok_a, "a.txt", b"aaa")
        r = self.client.post(
            f"/api/v1/workspaces/{other['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "stolen.txt", "if_none_match": True},
        )
        self.assertIn(r.status_code, (403, 404), r.text[:400])
        r = self.client.post("/api/v1/publish-requests/x/approve", headers=auth(self.tok_a))
        self.assertEqual(r.status_code, 403)

    def test_05_health_public_and_no_token_in_url(self):
        r = self.client.get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])
        self.assertTrue(r.json()["ready"])
        self.assertNotIn("token", r.text.lower())
        from agenthub_cli.cli import build_parser

        self.assertNotIn("--token", build_parser().format_help())
        self.assertNotIn("--insecure", build_parser().format_help())

    def test_06_files_budget(self):
        me = self.me(self.tok_a)
        r = self.client.get(
            f"/api/v1/workspaces/{me['workspace_id']}/files",
            headers=auth(self.tok_a),
            params={"limit": 2, "max_bytes": 200},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertIn("items", data)
        self.assertIn("returned_bytes", data)
        ctx = self.client.get("/api/v1/context", headers=auth(self.tok_a), params={"limit": 5})
        self.assertEqual(ctx.status_code, 200)

    def test_07_ordinary_upload_invisible_until_commit(self):
        data = b"hello-atomic"
        uid = self.upload(self.tok_a, "hello.txt", data)
        me = self.me(self.tok_a)
        listed = self.client.get(f"/api/v1/workspaces/{me['workspace_id']}/files", headers=auth(self.tok_a)).json()["data"]["items"]
        self.assertFalse(any(i["path"] == "notes/hello.txt" for i in listed))
        r = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "notes/hello.txt", "if_none_match": True},
        )
        self.assertEqual(r.status_code, 201, r.text[:400])
        listed = self.client.get(f"/api/v1/workspaces/{me['workspace_id']}/files", headers=auth(self.tok_a)).json()["data"]["items"]
        self.assertTrue(any(i["path"] == "notes/hello.txt" and i["sha256"] == sha(data) for i in listed))

    def test_08_content_mismatch(self):
        bad = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "x.txt", "bytes": 4, "sha256": sha(b"xxxx"), "purpose": "file"},
        )
        uid2 = bad.json()["data"]["upload_id"]
        put = self.client.put(f"/api/v1/uploads/{uid2}/content", headers=auth(self.tok_a), content=b"yyyy")
        self.assertIn(put.status_code, (413, 422))

    def test_09_quota_distinct(self):
        r = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "huge.bin", "bytes": 200 * 1024 * 1024 + 1, "sha256": "a" * 64, "purpose": "file"},
        )
        self.assertIn(r.status_code, (413, 422))

    def test_10_unknown_write_query_same_key(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.md", "# m\n")
        data = buf.getvalue()
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "pack10.zip", data, purpose="import")
        prev = self.preview(self.tok_a, uid, "mahler10")
        self.assertEqual(prev.status_code, 200, prev.text[:400])
        ph = prev.json()["data"]["manifest_hash"]
        pid = prev.json()["data"]["preview_id"]
        body = {"preview_id": pid, "manifest_hash": ph, "conflict": "fail"}
        r1 = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "op-import-10"},
            json=body,
        )
        self.assertEqual(r1.status_code, 202, r1.text[:400])
        op = self.client.get("/api/v1/operations/op-import-10", headers=auth(self.tok_a))
        self.assertEqual(op.status_code, 200)
        self.assertEqual(op.json()["data"]["job_id"], r1.json()["data"]["job_id"])

    def test_11_idempotent_conflict(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("only.md", "x")
        data = buf.getvalue()
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "pack11.zip", data, purpose="import")
        prev = self.preview(self.tok_a, uid, "mahler11")
        body = {"preview_id": prev.json()["data"]["preview_id"], "manifest_hash": prev.json()["data"]["manifest_hash"], "conflict": "fail"}
        r1 = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "op-import-11"},
            json=body,
        )
        self.assertEqual(r1.status_code, 202, r1.text[:400])
        r2 = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "op-import-11"},
            json=body,
        )
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r1.json()["data"]["job_id"], r2.json()["data"]["job_id"])
        r3 = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "op-import-11"},
            json={**body, "conflict": "replace"},
        )
        self.assertEqual(r3.status_code, 409)

    def test_12_etag_conflict(self):
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "e.txt", b"v1")
        self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "etag.txt", "if_none_match": True},
        )
        uid2 = self.upload(self.tok_a, "e.txt", b"v2")
        r = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid2, "path": "etag.txt", "if_match": "deadbeef"},
        )
        self.assertEqual(r.status_code, 412)
        listed = self.client.get(f"/api/v1/workspaces/{me['workspace_id']}/files", headers=auth(self.tok_a)).json()["data"]["items"]
        self.assertTrue(any(i["path"] == "etag.txt" and i["sha256"] == sha(b"v1") for i in listed))

    def test_13_zip_tar_skip_mac(self):
        me = self.me(self.tok_a)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ok.md", "x")
            zf.writestr("__MACOSX/._ok", "m")
            zf.writestr(".DS_Store", "s")
        uid = self.upload(self.tok_a, "ok.zip", buf.getvalue(), purpose="import")
        prev = self.preview(self.tok_a, uid, "okpack")
        self.assertEqual(prev.status_code, 200, prev.text[:400])
        self.assertEqual(prev.json()["data"]["file_count"], 1)
        tbuf = io.BytesIO()
        with tarfile.open(fileobj=tbuf, mode="w:gz") as tf:
            info = tarfile.TarInfo("kept.txt")
            payload = b"tar"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        uid2 = self.upload(self.tok_a, "ok.tar.gz", tbuf.getvalue(), purpose="import")
        prev2 = self.preview(self.tok_a, uid2, "targz")
        self.assertEqual(prev2.status_code, 200, prev2.text[:400])
        self.assertEqual(prev2.json()["data"]["file_count"], 1)

    def test_14_nested_zip_and_7z_attachment(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("inner.txt", "i")
        inner_bytes = inner.getvalue()
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("nested.zip", inner_bytes)
        uid = self.upload(self.tok_a, "outer.zip", outer.getvalue(), purpose="import")
        prev = self.preview(self.tok_a, uid, "nest")
        self.assertEqual(prev.status_code, 200, prev.text[:400])
        paths = [m["path"] for m in prev.json()["data"]["members"]]
        self.assertEqual(paths, ["nested.zip"])
        fake7z = b"7z\xbc\xaf'\x1c" + b"not-an-archive"
        uid7 = self.upload(self.tok_a, "pack.7z", fake7z, purpose="import")
        prev7 = self.preview(self.tok_a, uid7, "seven")
        self.assertEqual(prev7.status_code, 422)
        me = self.me(self.tok_a)
        commit = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid7, "path": "pack.7z", "if_none_match": True},
        )
        self.assertEqual(commit.status_code, 201, commit.text[:400])

    def test_15_dangerous_paths(self):
        slip = io.BytesIO()
        with zipfile.ZipFile(slip, "w") as zf:
            zf.writestr("../x.txt", "no")
        uid = self.upload(self.tok_a, "slip.zip", slip.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid, "slip").status_code, (422, 400))
        absz = io.BytesIO()
        with zipfile.ZipFile(absz, "w") as zf:
            zf.writestr("/tmp/x.txt", "no")
        uid2 = self.upload(self.tok_a, "abs.zip", absz.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid2, "abs").status_code, (422, 400))

    def test_16_links_duplicates_casefold(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("A.md", "1")
            zf.writestr("a.md", "2")
        uid = self.upload(self.tok_a, "dup.zip", buf.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid, "dup").status_code, (422, 400))
        tbuf = io.BytesIO()
        with tarfile.open(fileobj=tbuf, mode="w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            tf.addfile(info)
        uid2 = self.upload(self.tok_a, "link.tar", tbuf.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid2, "link").status_code, (422, 400))

    def test_17_archive_resource_limits(self):
        with connect() as conn:
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('import_members','1')")
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("a.txt", "a")
                zf.writestr("b.txt", "b")
            uid = self.upload(self.tok_a, "many.zip", buf.getvalue(), purpose="import")
            self.assertIn(self.preview(self.tok_a, uid, "many").status_code, (413, 422))
        finally:
            with connect() as conn:
                conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('import_members','5000')")

    def test_18_encrypted_git_exe(self):
        enc = io.BytesIO()
        with zipfile.ZipFile(enc, "w") as zf:
            zf.writestr("secret.txt", "x")
        blob = bytearray(enc.getvalue())
        for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while True:
                i = blob.find(sig, start)
                if i < 0:
                    break
                flags = int.from_bytes(blob[i + flag_off : i + flag_off + 2], "little") | 1
                blob[i + flag_off : i + flag_off + 2] = flags.to_bytes(2, "little")
                start = i + 4
        uid = self.upload(self.tok_a, "enc.zip", bytes(blob), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid, "enc").status_code, (422, 400))
        git = io.BytesIO()
        with zipfile.ZipFile(git, "w") as zf:
            zf.writestr(".git/config", "x")
        uid2 = self.upload(self.tok_a, "git.zip", git.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid2, "git").status_code, (422, 400))
        exe = io.BytesIO()
        with zipfile.ZipFile(exe, "w") as zf:
            zf.writestr("tool.exe", "MZ")
        uid3 = self.upload(self.tok_a, "exe.zip", exe.getvalue(), purpose="import")
        self.assertIn(self.preview(self.tok_a, uid3, "exe").status_code, (422, 400))

    def test_19_job_query_after_success(self):
        r = self.client.get("/api/v1/jobs/missing", headers=auth(self.tok_a))
        self.assertEqual(r.status_code, 404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("j.md", "j")
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "job.zip", buf.getvalue(), purpose="import")
        prev = self.preview(self.tok_a, uid, "jobdir")
        body = {"preview_id": prev.json()["data"]["preview_id"], "manifest_hash": prev.json()["data"]["manifest_hash"], "conflict": "fail"}
        r1 = self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "op-job-19"},
            json=body,
        )
        self.assertEqual(r1.status_code, 202, r1.text[:400])
        job = self.client.get(f"/api/v1/jobs/{r1.json()['data']['job_id']}", headers=auth(self.tok_a))
        self.assertEqual(job.json()["data"]["state"], "succeeded")

    def test_20_download_path_and_no_delete(self):
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "d.txt", b"dl")
        self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "down.txt", "if_none_match": True},
        )
        r = self.client.get(
            f"/api/v1/workspaces/{me['workspace_id']}/files/content",
            headers=auth(self.tok_a),
            params={"path": "down.txt"},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"dl")
        r = self.client.get(
            f"/api/v1/workspaces/{me['workspace_id']}/files/content",
            headers=auth(self.tok_a),
            params={"path": "../etc/passwd"},
        )
        self.assertIn(r.status_code, (404, 422))

    def test_21_publish_queued_not_created(self):
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "p.md", b"# p")
        self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "pub/a.md", "if_none_match": True},
        )
        plan = self.client.post(
            "/api/v1/publish/plans",
            headers=auth(self.tok_a),
            json={"prefix": "pub", "repo": "sunnyspot114514/cli-mock-repo", "mode": "create", "visibility": "public", "license": "MIT", "copyright_holder": "Xiwei Chen"},
        )
        self.assertEqual(plan.status_code, 201, plan.text[:400])
        pdata = plan.json()["data"]
        self.assertIn("MIT", pdata["license"])
        req = self.client.post(
            "/api/v1/publish/requests",
            headers=auth(self.tok_a),
            json={"plan_id": pdata["plan_id"], "manifest_hash": pdata["manifest_hash"]},
        )
        self.assertEqual(req.status_code, 201, req.text[:400])
        self.assertEqual(req.json()["data"]["state"], "awaiting_approval")
        rid = req.json()["data"]["request_id"]
        deny = self.client.post(f"/api/v1/publish-requests/{rid}/approve", headers=auth(self.tok_a))
        self.assertEqual(deny.status_code, 403)
        got = self.client.get(f"/api/v1/publish/requests/{rid}", headers=auth(self.tok_a))
        self.assertEqual(got.json()["data"]["state"], "awaiting_approval")
        self.assertNotIn("github.com", json.dumps(got.json()))

    def test_22_plan_freeze_hash(self):
        me = self.me(self.tok_a)
        uid = self.upload(self.tok_a, "later.md", b"# later")
        self.client.post(
            f"/api/v1/workspaces/{me['workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "pub/later.md", "if_none_match": True},
        )
        plan = self.client.post(
            "/api/v1/publish/plans",
            headers=auth(self.tok_a),
            json={"prefix": "pub", "repo": "sunnyspot114514/cli-mock-repo", "mode": "create", "visibility": "public", "license": "MIT", "copyright_holder": "Xiwei Chen"},
        )
        pdata = plan.json()["data"]
        req = self.client.post(
            "/api/v1/publish/requests",
            headers=auth(self.tok_a),
            json={"plan_id": pdata["plan_id"], "manifest_hash": "0" * 64},
        )
        self.assertEqual(req.status_code, 412)

    def test_23_mock_no_force_claim(self):
        caps = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        self.assertFalse(caps["features"]["publish_approve"])
        self.assertIn("approve_own_publish", caps["cannot"])
        self.assertTrue(caps["features"]["publish_request"])

    def test_24_json_stdout_cli_version(self):
        from agenthub_cli import __version__

        self.assertEqual(__version__, "0.1.0")
        self.assertEqual(sys.platform.startswith("win"), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
