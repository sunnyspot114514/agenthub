from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agenthub_cli import __version__
from agenthub_cli import auth as authmod
from agenthub_cli import config as cfgmod
from agenthub_cli.client import HubClient, sha256_file
from agenthub_cli.errors import CliError
from agenthub_cli.output import emit_json, warn


def _client(args) -> HubClient:
    base = getattr(args, "base_url", None) or cfgmod.load().get("base_url") or ""
    token = authmod.load_token(allow_store=True)
    return HubClient(base, token)


def _data(body: dict):
    return body.get("data", body)


def cmd_config(args) -> int:
    if args.action == "set" and args.key == "base-url":
        cfgmod.set_base_url(args.value)
        emit_json({"ok": True, "base_url": cfgmod.load().get("base_url")})
        return 0
    emit_json({"config": {k: v for k, v in cfgmod.load().items() if k != "token"}})
    return 0


def cmd_auth(args) -> int:
    if args.action == "logout":
        authmod.clear_local()
        emit_json({"ok": True, "cleared": "local"})
        return 0
    token = authmod.load_token(allow_store=True)
    if args.action == "status":
        if not token:
            emit_json({"authenticated": False, "source": None})
            return 3
        c = _client(args)
        try:
            me = _data(c.json("GET", "/api/v1/me"))
        except CliError as exc:
            emit_json(exc.payload)
            return exc.exit_code
        emit_json(
            {
                "authenticated": True,
                "source": "env" if authmod.token_from_env() else "store",
                "identity": me.get("identity"),
                "scopes": me.get("scopes"),
                "disabled": me.get("disabled"),
            }
        )
        return 0
    if args.action == "login":
        import getpass

        token = getpass.getpass("Agenthub token: ")
        if not token.strip():
            return 3
        if args.store == "keyring":
            src = authmod.store_token(token.strip())
        else:
            src = "not-stored"
            warn("token not saved; export AGENTHUB_TOKEN for this process")
        emit_json({"ok": True, "stored": src})
        return 0
    return 2


def cmd_whoami(args) -> int:
    c = _client(args)
    emit_json(_data(c.json("GET", "/api/v1/me")))
    return 0


def cmd_capabilities(args) -> int:
    c = _client(args)
    body = _data(c.json("GET", "/api/v1/capabilities"))
    min_v = str(body.get("min_client_version") or "0.1.0")
    if tuple(int(x) for x in min_v.split(".")[:3]) > tuple(int(x) for x in __version__.split(".")[:3]):
        raise CliError("client too old", 10, {"error": {"code": "incompatible", "message": "client too old"}})
    emit_json(body)
    return 0


def cmd_workspace(args) -> int:
    c = _client(args)
    me = _data(c.json("GET", "/api/v1/me"))
    wid = me["workspace_id"]
    if args.action == "ls":
        emit_json(_data(c.json("GET", f"/api/v1/workspaces/{wid}/files", params={"limit": args.limit, "max_bytes": args.max_bytes})))
        return 0
    if args.action == "get":
        resp = c.request("GET", f"/api/v1/workspaces/{wid}/files/content", params={"path": args.path})
        if resp.status_code >= 400:
            raise CliError("download failed", 5)
        Path(args.out).write_bytes(resp.content)
        emit_json({"ok": True, "out": args.out, "bytes": len(resp.content)})
        return 0
    if args.action == "put":
        if args.manifest:
            items = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            rows = items.get("files") if isinstance(items, dict) else items
            if args.dry_run:
                emit_json({"dry_run": True, "files": rows, "deletes": False})
                return 0
            results = []
            for row in rows:
                src = Path(row["src"])
                size, digest = sha256_file(src)
                decl = _data(c.json("POST", "/api/v1/uploads", json={"name": src.name, "bytes": size, "sha256": digest, "purpose": "file"}))
                c.put_bytes(decl["content_path"], src.read_bytes())
                body = {"upload_id": decl["upload_id"], "path": row["path"], "if_none_match": bool(args.if_none_match)}
                results.append(_data(c.json("POST", f"/api/v1/workspaces/{wid}/files/commit", json=body)))
            emit_json({"ok": True, "items": results})
            return 0
        if not args.src or not args.path:
            raise CliError("src and --path required", 2)
        src = Path(args.src)
        size, digest = sha256_file(src)
        if args.dry_run:
            emit_json({"dry_run": True, "path": args.path, "bytes": size, "sha256": digest})
            return 0
        decl = _data(c.json("POST", "/api/v1/uploads", json={"name": src.name, "bytes": size, "sha256": digest, "purpose": "file"}))
        c.put_bytes(decl["content_path"], src.read_bytes())
        body = {"upload_id": decl["upload_id"], "path": args.path, "if_none_match": bool(args.if_none_match)}
        if args.if_match:
            body["if_match"] = args.if_match
        emit_json(_data(c.json("POST", f"/api/v1/workspaces/{wid}/files/commit", json=body)))
        return 0
    if args.action == "import":
        src = Path(args.src)
        size, digest = sha256_file(src)
        if args.dry_run:
            decl = _data(c.json("POST", "/api/v1/uploads", json={"name": src.name, "bytes": size, "sha256": digest, "purpose": "import"}))
            c.put_bytes(decl["content_path"], src.read_bytes())
            prev = _data(c.json("POST", f"/api/v1/workspaces/{wid}/imports/preview", json={"upload_id": decl["upload_id"], "dest": args.dest}))
            emit_json({"dry_run": True, **prev})
            return 0
        decl = _data(c.json("POST", "/api/v1/uploads", json={"name": src.name, "bytes": size, "sha256": digest, "purpose": "import"}))
        c.put_bytes(decl["content_path"], src.read_bytes())
        prev = _data(c.json("POST", f"/api/v1/workspaces/{wid}/imports/preview", json={"upload_id": decl["upload_id"], "dest": args.dest}))
        headers = {}
        if args.idempotency_key:
            headers["Idempotency-Key"] = args.idempotency_key
        out = c.json(
            "POST",
            f"/api/v1/workspaces/{wid}/imports",
            json={"preview_id": prev["preview_id"], "manifest_hash": prev["manifest_hash"], "conflict": args.conflict},
            headers=headers,
        )
        emit_json(_data(out) if "data" in out else out)
        return 0
    if args.action == "export":
        listing = _data(c.json("GET", f"/api/v1/workspaces/{wid}/files", params={"limit": 200, "max_bytes": 1_000_000}))
        emit_json({"items": listing.get("items"), "note": "content not bundled; use workspace get"})
        return 0
    return 2


def cmd_publish(args) -> int:
    c = _client(args)
    if args.action == "plan":
        body = {
            "prefix": args.prefix,
            "repo": args.repo,
            "mode": args.mode,
            "visibility": args.visibility,
            "license": args.license,
            "copyright_holder": args.copyright_holder,
        }
        plan = _data(c.json("POST", "/api/v1/publish/plans", json=body))
        if args.out:
            Path(args.out).write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        emit_json(plan)
        return 0
    if args.action == "request":
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        out = _data(c.json("POST", "/api/v1/publish/requests", json={"plan_id": plan["plan_id"], "manifest_hash": plan["manifest_hash"]}))
        emit_json(out)
        return 0
    if args.action in {"status", "watch"}:
        out = _data(c.json("GET", f"/api/v1/publish-requests/{args.request_id}"))
        emit_json(out)
        return 0
    warn("approve is not a client command")
    return 4


def cmd_stub(args) -> int:
    raise CliError("command not in v0.1.0", 10, {"error": {"code": "incompatible", "message": args.cmd + " not implemented"}})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agenthub")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--json", action="store_true", default=True)
    p.add_argument("--base-url", default="")
    sub = p.add_subparsers(dest="cmd")

    cfg = sub.add_parser("config")
    cfg.add_argument("action", choices=["set", "show"])
    cfg.add_argument("key", nargs="?")
    cfg.add_argument("value", nargs="?")
    cfg.set_defaults(func=cmd_config)

    auth = sub.add_parser("auth")
    auth.add_argument("action", choices=["login", "status", "logout"])
    auth.add_argument("--store", choices=["none", "keyring"], default="none")
    auth.set_defaults(func=cmd_auth)

    who = sub.add_parser("whoami")
    who.set_defaults(func=cmd_whoami)
    cap = sub.add_parser("capabilities")
    cap.set_defaults(func=cmd_capabilities)

    ws = sub.add_parser("workspace")
    ws_sub = ws.add_subparsers(dest="action", required=True)
    ls = ws_sub.add_parser("ls")
    ls.add_argument("--owner", default="me")
    ls.add_argument("--limit", type=int, default=50)
    ls.add_argument("--max-bytes", dest="max_bytes", type=int, default=16384)
    ls.set_defaults(func=cmd_workspace)
    getp = ws_sub.add_parser("get")
    getp.add_argument("path")
    getp.add_argument("--out", required=True)
    getp.set_defaults(func=cmd_workspace)
    put = ws_sub.add_parser("put")
    put.add_argument("src", nargs="?")
    put.add_argument("--path", default="")
    put.add_argument("--manifest", default="")
    put.add_argument("--if-none-match", action="store_true")
    put.add_argument("--if-match", default="")
    put.add_argument("--dry-run", action="store_true")
    put.set_defaults(func=cmd_workspace)
    imp = ws_sub.add_parser("import")
    imp.add_argument("src")
    imp.add_argument("--dest", required=True)
    imp.add_argument("--dry-run", action="store_true")
    imp.add_argument("--conflict", default="fail")
    imp.add_argument("--wait", action="store_true")
    imp.add_argument("--idempotency-key", default="")
    imp.set_defaults(func=cmd_workspace)
    exp = ws_sub.add_parser("export")
    exp.set_defaults(func=cmd_workspace)

    pub = sub.add_parser("publish")
    pub_sub = pub.add_subparsers(dest="action", required=True)
    plan = pub_sub.add_parser("plan")
    plan.add_argument("--from", dest="prefix", default="")
    plan.add_argument("--repo", required=True)
    plan.add_argument("--mode", default="create")
    plan.add_argument("--visibility", default="public")
    plan.add_argument("--license", default="MIT")
    plan.add_argument("--copyright-holder", default="Xiwei Chen")
    plan.add_argument("--out", default="")
    plan.set_defaults(func=cmd_publish)
    req = pub_sub.add_parser("request")
    req.add_argument("--plan", required=True)
    req.set_defaults(func=cmd_publish)
    st = pub_sub.add_parser("status")
    st.add_argument("request_id")
    st.set_defaults(func=cmd_publish)
    wt = pub_sub.add_parser("watch")
    wt.add_argument("request_id")
    wt.set_defaults(func=cmd_publish)

    for name in ("chat", "logs", "brief", "context"):
        sp = sub.add_parser(name)
        sp.set_defaults(func=cmd_stub, cmd=name)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args) or 0)
    except CliError as exc:
        emit_json(exc.payload)
        return exc.exit_code
    except Exception as exc:
        warn(type(exc).__name__)
        emit_json({"error": {"message": type(exc).__name__, "code": "client"}})
        return 8


if __name__ == "__main__":
    raise SystemExit(main())
