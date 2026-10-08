#!/usr/bin/env python3
"""Agenthub 1.5 URL-first discovery tests. Never prints secrets."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agenthub-cli" / "src"))

TMP = tempfile.mkdtemp(prefix="agenthub-v15-")
os.environ["AGENTHUB_ROOT"] = TMP
os.environ["AGENTHUB_DB"] = str(Path(TMP) / "data" / "hub.db")
os.environ["AGENTHUB_ALLOW_TEST_CLOCK"] = "1"
os.environ["AGENTHUB_API_TOKEN"] = "test-admin-token-xxxxxxxx"
os.environ["AGENTHUB_SESSION_SECRET"] = "test-session-secret-32-bytes-long"
os.environ["AGENTHUB_PUBLIC_HOST"] = "agenthub.example.test"

from fastapi.testclient import TestClient  # noqa: E402

import app as hub  # noqa: E402
from hubv1.discovery import DISCOVERY_BUDGET, validate_bootstrap  # noqa: E402
from hubv1.store import connect, refresh_paths  # noqa: E402


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class V15Tests(unittest.TestCase):
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
        with connect() as conn:
            conn.execute("UPDATE hub_config SET value='1' WHERE key='feature_publisher'")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('mit_copyright_holder','sunnyspot114514')")
            conn.execute("INSERT OR REPLACE INTO hub_config(key,value) VALUES ('publisher_allowed_owners','[\"sunnyspot114514\"]')")
        cls.client = TestClient(hub.app)
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-a-v15"},
            json={"agent_id": "agent_a", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own", "publish:request"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-b-v15"},
            json={"agent_id": "agent_b", "roles": ["view", "report"], "project_ids": [], "scopes": ["chat:write", "workspace:write:own"]},
        )
        cls.client.post(
            "/api/v1/grants",
            headers={**auth(cls.admin), "Idempotency-Key": "g-r-v15"},
            json={"agent_id": "agent_r", "roles": ["view"], "project_ids": [], "scopes": ["chat:write"]},
        )

    def test_01_anonymous_discovery(self):
        agent = self.client.get("/agent")
        self.assertEqual(agent.status_code, 200)
        self.assertIn("markdown", agent.headers.get("content-type", "").lower())
        self.assertLessEqual(len(agent.content), 12 * 1024)
        self.assertIn("持 token 的 Agent 接入", self.client.get("/").text)
        boot = self.client.get("/agent/bootstrap.json")
        self.assertEqual(boot.status_code, 200)
        self.assertIn("json", boot.headers.get("content-type", "").lower())
        self.assertLessEqual(len(boot.content), 4 * 1024)
        data = boot.json()
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(validate_bootstrap(data), [])
        self.assertFalse(bool(self.client.cookies))

    def test_02_edge_network(self):
        local = self.client.get("/agent")
        self.assertEqual(local.status_code, 200)
        live_status = None
        live_body = b""
        try:
            req = urllib.request.Request("https://agenthub.sunny99.win/agent", method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                live_status = resp.status
                live_body = resp.read(400)
        except urllib.error.HTTPError as exc:
            live_status = exc.code
            live_body = exc.read(400)
        except Exception:
            live_status = 0
        if live_status == 200:
            self.assertTrue(live_body.startswith(b"#") or b"Agenthub" in live_body)
            return
        # 404: not deployed. 403/challenge: record and do not bypass (no cookies, -k, or alt UA).
        sys.stderr.write(f"live /agent status={live_status} deployed=false not_bypassed\n")
        self.assertIn(live_status, {0, 403, 404, 429, 502, 503, 530}, f"unexpected live {live_status}")

    def test_03_public_sanitized(self):
        blob = self.client.get("/agent").text + self.client.get("/agent/bootstrap.json").text + self.client.get("/").text
        for needle in (self.tok_a, self.admin, "192.168.", "127.0.0.1:8000", "hub-shared", "chat_messages"):
            self.assertNotIn(needle, blob)
        spec = self.client.get("/openapi.json").json()
        paths = spec.get("paths") or {}
        self.assertNotIn("/console", "".join(paths))
        self.assertFalse(any(p.startswith("/console") or p.startswith("/mcp") for p in paths))

    def test_04_contract_matches_router(self):
        spec = self.client.get("/openapi.json").json()
        router_paths = {getattr(r, "path", "") for r in hub.app.routes}
        for path, methods in (spec.get("paths") or {}).items():
            self.assertTrue(any(path == rp or rp.startswith(path.split("{")[0]) for rp in router_paths) or path in router_paths)
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                self.assertTrue(op.get("operationId") or method)
                if path in hub.PUBLIC_PATHS or path.startswith("/v1/public/"):
                    self.assertEqual(op.get("security"), [])
                elif path.startswith("/api/"):
                    self.assertEqual(op.get("security"), [{"bearerAuth": []}])
                    self.assertIn("401", op.get("responses") or {})
        self.assertNotIn("/api/v1/uploads/{id}/resume", spec.get("paths") or {})

    def test_05_auth_rejects_json(self):
        r = self.client.get("/api/v1/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "unauthorized")
        self.assertNotIn("login", r.headers.get("location", "").lower())
        r = self.client.get("/api/v1/me", headers=auth("nope-nope-nope-nope"))
        self.assertEqual(r.status_code, 401)
        self.assertIn("no-store", r.headers.get("Cache-Control", "").lower())

    def test_06_permission_isolation(self):
        caps_r = self.client.get("/api/v1/capabilities", headers=auth(self.tok_r)).json()["data"]
        self.assertFalse(caps_r["features"]["workspace_write_own"])
        self.assertFalse(caps_r["features"]["publish_approve"])
        me_a = self.client.get("/api/v1/me", headers=auth(self.tok_a)).json()["data"]
        me_b = self.client.get("/api/v1/me", headers=auth(self.tok_b)).json()["data"]
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "x.txt", "bytes": 4, "sha256": sha(b"abcd"), "purpose": "file"},
        )
        uid = decl.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(self.tok_a), content=b"abcd")
        own = self.client.post(
            f"/api/v1/workspaces/{me_a['own_workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "v15/own.txt", "if_none_match": True},
        )
        self.assertEqual(own.status_code, 201, own.text[:300])
        other = self.client.post(
            f"/api/v1/workspaces/{me_b['own_workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "stolen.txt", "if_none_match": True},
        )
        self.assertIn(other.status_code, (403, 404))
        self.assertEqual(self.client.post("/api/v1/publish-requests/x/approve", headers=auth(self.tok_a)).status_code, 403)

    def test_07_capabilities_truthful(self):
        caps = self.client.get("/api/v1/capabilities", headers=auth(self.tok_a)).json()["data"]
        from hubv1.version import APP_VERSION

        self.assertEqual(caps["api_version"], APP_VERSION)
        self.assertEqual(caps["api_version"], hub.APP_VERSION)
        self.assertTrue(caps["features"]["binary_upload"])
        self.assertTrue(caps["features"]["workspace_write_own"])
        self.assertFalse(caps["features"]["resumable_upload"])
        self.assertIsNone(caps["limits"]["proxy_receive_bytes"])
        self.assertIsInstance(caps["limits"]["workspace_remaining_bytes"], int)
        self.assertEqual(caps["links"]["context"], "/api/v1/context")
        caps_r = self.client.get("/api/v1/capabilities", headers=auth(self.tok_r)).json()["data"]
        self.assertFalse(caps_r["features"]["atomic_import"])
        self.assertFalse(caps_r["features"]["publish_request"])

    def test_08_same_origin_tls_rules(self):
        from hubv1.discovery import same_origin_api, validate_bootstrap

        boot = self.client.get("/agent/bootstrap.json").json()
        origin = "https://agenthub.sunny99.win"
        self.assertTrue(same_origin_api(boot["api_root"], origin))
        self.assertFalse(same_origin_api("https://evil.example/api/v1", origin))
        self.assertFalse(same_origin_api("http://agenthub.sunny99.win/api/v1", origin))
        evil = dict(boot)
        evil["api_root"] = "https://evil.example/steal"
        self.assertTrue(validate_bootstrap(evil))
        from agenthub_cli.client import HubClient
        from agenthub_cli.errors import CliError

        c = HubClient("https://agenthub.example.test", "x")
        with self.assertRaises(CliError):
            c.request("GET", "https://evil.example/api/v1/me")

    def test_09_credential_hygiene(self):
        from agenthub_cli.cli import build_parser

        help_text = build_parser().format_help()
        self.assertNotIn("--token", help_text)
        examples = Path(__file__).resolve().parent.joinpath("docs/http-examples.md").read_text(encoding="utf-8")
        self.assertNotIn("Bearer ey", examples)
        self.assertNotIn(self.tok_a, examples)

    def test_10_byte_budget(self):
        agent = self.client.get("/agent").content
        boot = self.client.get("/agent/bootstrap.json").content
        self.assertLessEqual(len(agent) + len(boot), DISCOVERY_BUDGET)
        ctx = self.client.get(
            "/api/v1/context",
            headers=auth(self.tok_a),
            params={"limit": 5, "max_bytes": 4096},
        )
        self.assertEqual(ctx.status_code, 200)
        data = ctx.json()["data"]
        self.assertIn("own_workspace_files", data)
        self.assertLessEqual(len(ctx.content), 8192)
        self.assertNotIn(self.tok_a, ctx.text)

    def test_11_http_without_cli(self):
        r = self.client.get("/agent/bootstrap.json")
        self.assertEqual(r.status_code, 200)
        me = self.client.get("/api/v1/me", headers=auth(self.tok_a))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["data"]["identity_id"], "agent_a")
        src = Path(__file__).resolve().parent / "docs" / "examples" / "auth_read.py"
        self.assertTrue(src.is_file())
        self.assertNotIn("agenthub_cli", src.read_text(encoding="utf-8"))

    def test_12_tiny_file_roundtrip(self):
        me = self.client.get("/api/v1/me", headers=auth(self.tok_a)).json()["data"]
        data = b"v15-roundtrip"
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "rt.txt", "bytes": len(data), "sha256": sha(data), "purpose": "file"},
        )
        uid = decl.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(self.tok_a), content=data)
        c1 = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "v15/rt.txt", "if_none_match": True},
        )
        self.assertEqual(c1.status_code, 201, c1.text[:300])
        got = self.client.get(
            f"/api/v1/workspaces/{me['own_workspace_id']}/files/content",
            headers=auth(self.tok_a),
            params={"path": "v15/rt.txt"},
        )
        self.assertEqual(got.content, data)
        stale = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "v15/rt.txt", "if_match": "deadbeef"},
        )
        self.assertEqual(stale.status_code, 412)

    def test_13_atomic_archive(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("inner.txt", "keep")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("nested.zip", inner.getvalue())
            zf.writestr("ok.md", "x")
        blob = outer.getvalue()
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "pack.zip", "bytes": len(blob), "sha256": sha(blob), "purpose": "import"},
        )
        uid = decl.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(self.tok_a), content=blob)
        me = self.client.get("/api/v1/me", headers=auth(self.tok_a)).json()["data"]
        prev = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/imports/preview",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "dest": "v15pack"},
        )
        self.assertEqual(prev.status_code, 200, prev.text[:300])
        paths = [m["path"] for m in prev.json()["data"]["members"]]
        self.assertEqual(sorted(paths), ["nested.zip", "ok.md"])
        slip = io.BytesIO()
        with zipfile.ZipFile(slip, "w") as zf:
            zf.writestr("../x.txt", "no")
        sblob = slip.getvalue()
        d2 = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "slip.zip", "bytes": len(sblob), "sha256": sha(sblob), "purpose": "import"},
        )
        u2 = d2.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{u2}/content", headers=auth(self.tok_a), content=sblob)
        bad = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/imports/preview",
            headers=auth(self.tok_a),
            json={"upload_id": u2, "dest": "slip"},
        )
        self.assertIn(bad.status_code, (400, 422))

    def test_14_jobs_and_error_codes(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("j.md", "j")
        blob = buf.getvalue()
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "job.zip", "bytes": len(blob), "sha256": sha(blob), "purpose": "import"},
        )
        uid = decl.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(self.tok_a), content=blob)
        me = self.client.get("/api/v1/me", headers=auth(self.tok_a)).json()["data"]
        prev = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/imports/preview",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "dest": "v15job"},
        )
        body = {"preview_id": prev.json()["data"]["preview_id"], "manifest_hash": prev.json()["data"]["manifest_hash"], "conflict": "fail"}
        r1 = self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/imports",
            headers={**auth(self.tok_a), "Idempotency-Key": "v15-op-1"},
            json=body,
        )
        self.assertEqual(r1.status_code, 202, r1.text[:300])
        job = self.client.get(f"/api/v1/jobs/{r1.json()['data']['job_id']}", headers=auth(self.tok_a))
        self.assertEqual(job.json()["data"]["state"], "succeeded")
        op = self.client.get("/api/v1/operations/v15-op-1", headers=auth(self.tok_a))
        self.assertEqual(op.status_code, 200)
        too = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "huge.bin", "bytes": 200 * 1024 * 1024 + 2, "sha256": "a" * 64, "purpose": "file"},
        )
        self.assertIn(too.status_code, (413, 422))
        self.assertTrue(too.json().get("error", {}).get("code"))

    def test_15_publish_mock_pending(self):
        me = self.client.get("/api/v1/me", headers=auth(self.tok_a)).json()["data"]
        data = b"# mock"
        decl = self.client.post(
            "/api/v1/uploads",
            headers=auth(self.tok_a),
            json={"name": "p.md", "bytes": len(data), "sha256": sha(data), "purpose": "file"},
        )
        uid = decl.json()["data"]["upload_id"]
        self.client.put(f"/api/v1/uploads/{uid}/content", headers=auth(self.tok_a), content=data)
        self.client.post(
            f"/api/v1/workspaces/{me['own_workspace_id']}/files/commit",
            headers=auth(self.tok_a),
            json={"upload_id": uid, "path": "pub15/a.md", "if_none_match": True},
        )
        plan = self.client.post(
            "/api/v1/publish/plans",
            headers=auth(self.tok_a),
            json={"prefix": "pub15", "repo": "sunnyspot114514/cli-mock-repo", "mode": "create", "visibility": "public", "license": "MIT", "copyright_holder": "sunnyspot114514"},
        )
        self.assertEqual(plan.status_code, 201, plan.text[:300])
        req = self.client.post(
            "/api/v1/publish/requests",
            headers=auth(self.tok_a),
            json={"plan_id": plan.json()["data"]["plan_id"], "manifest_hash": plan.json()["data"]["manifest_hash"]},
        )
        self.assertEqual(req.status_code, 201, req.text[:300])
        self.assertEqual(req.json()["data"]["state"], "awaiting_approval")
        self.assertNotIn("github.com", json.dumps(req.json()))
        # remote_publish_verified: not claimed


if __name__ == "__main__":
    unittest.main(verbosity=2)
