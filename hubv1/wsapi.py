"""Workspace, capabilities, jobs, and publish routes. Attached from api.py to avoid import cycles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError

from hubv1.acl import Access
from hubv1.flags import flag
from hubv1.store import connect, dumps
from hubv1 import publisher
from hubv1 import workspace as ws


class NodeIn(BaseModel):
    parent_id: Optional[str] = None
    name: str = Field(min_length=1, max_length=160)
    kind: str = "file"
    body: str = ""
    mime_type: str = "text/plain"
    admin_reason: str = ""
    author: Optional[str] = None
    owner_agent_id: Optional[str] = None
    workspace_id: Optional[str] = None


class NodeUpdate(BaseModel):
    expected_revision: int
    body: Optional[str] = None
    mime_type: str = ""
    name: Optional[str] = None
    admin_reason: str = ""
    author: Optional[str] = None
    owner_agent_id: Optional[str] = None


class NodeMove(BaseModel):
    parent_id: str
    expected_revision: int
    name: Optional[str] = None
    admin_reason: str = ""


class NodeRev(BaseModel):
    expected_revision: int
    admin_reason: str = ""


class PublishIn(BaseModel):
    node_ids: list[str] = Field(default_factory=list)
    target_owner: str = Field(min_length=1, max_length=80)
    repo: str = Field(min_length=1, max_length=80)
    branch: str = "main"
    create_repo: bool = False
    author: Optional[str] = None


def _deny_without_publish(acc: Access) -> None:
    if not publisher.actor_can_request(acc):
        raise HTTPException(status_code=403, detail="forbidden")


async def _json_model(request: Request, model):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors())


def _reject_spoof(acc: Access, body: Any) -> None:
    author = getattr(body, "author", None)
    owner = getattr(body, "owner_agent_id", None)
    if author and author != acc.p.id:
        raise HTTPException(status_code=403, detail="author mismatch; server binds actor from token")
    if owner and owner != acc.p.id and not acc.manage:
        raise HTTPException(status_code=403, detail="owner_agent_id ignored; workspace is bound to identity")


def _http(exc: Exception):
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc) or "forbidden")
    if isinstance(exc, KeyError):
        raise HTTPException(status_code=404, detail="not found")
    if isinstance(exc, FileExistsError):
        raise HTTPException(status_code=409, detail="name conflict")
    if isinstance(exc, RuntimeError) and str(exc) == "conflict":
        raise HTTPException(status_code=409, detail="revision conflict")
    if isinstance(exc, OverflowError):
        raise HTTPException(status_code=413, detail=str(exc) or "too large")
    if isinstance(exc, MemoryError):
        raise HTTPException(status_code=507, detail="quota exceeded")
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=400, detail=str(exc))
    raise exc


def attach(router, shared_router, *, require_api, envelope, require_idem, replay_or_store):
    @router.get("/workspaces")
    def list_workspaces(request: Request, acc: Access = Depends(require_api("view"))):
        if not ws.enabled():
            raise HTTPException(status_code=404, detail="workspace disabled")
        items = [w for w in ws.list_workspaces() if ws.can_read_workspace(acc, w)]
        return envelope(request, {"items": items})

    @router.get("/workspaces/me")
    def my_workspace(request: Request, acc: Access = Depends(require_api("view"))):
        if not ws.enabled():
            raise HTTPException(status_code=404, detail="workspace disabled")
        mine = ws.workspace_of(acc.p.id)
        if not mine or not ws.can_read_workspace(acc, mine):
            raise HTTPException(status_code=404, detail="not found")
        mine["writable"] = ws.can_write_workspace(acc, mine)
        return envelope(request, mine)

    @router.get("/workspaces/{workspace_id}/nodes")
    def list_nodes(
        workspace_id: str,
        request: Request,
        parent_id: Optional[str] = None,
        acc: Access = Depends(require_api("view")),
    ):
        if not ws.enabled():
            raise HTTPException(status_code=404, detail="workspace disabled")
        w = ws.get_workspace(workspace_id)
        if not w or not ws.can_read_workspace(acc, w):
            raise HTTPException(status_code=404, detail="not found")
        return envelope(request, {"workspace_id": workspace_id, "items": ws.list_children(workspace_id, parent_id)})

    @router.post("/workspaces/me/nodes")
    def create_my_node(body: NodeIn, request: Request, acc: Access = Depends(require_api("view"))):
        _reject_spoof(acc, body)
        mine = ws.workspace_of(acc.p.id)
        if not mine:
            raise HTTPException(status_code=404, detail="not found")
        if body.workspace_id and body.workspace_id != mine["workspace_id"] and not acc.manage:
            raise HTTPException(status_code=403, detail="cannot create in another workspace")
        target = body.workspace_id if acc.manage and body.workspace_id else mine["workspace_id"]
        try:
            info = ws.create_node(
                acc,
                workspace_id=target,
                parent_id=body.parent_id,
                name=body.name,
                kind=body.kind,
                data=(body.body or "").encode("utf-8") if body.kind == "file" else b"",
                mime=body.mime_type,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=body.admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info, status=201)

    @router.post("/workspaces/me/uploads")
    async def upload_my_node(
        request: Request,
        file: UploadFile = File(...),
        acc: Access = Depends(require_api("view")),
        parent_id: Optional[str] = None,
        admin_reason: str = "",
    ):
        mine = ws.workspace_of(acc.p.id)
        if not mine:
            raise HTTPException(status_code=404, detail="not found")
        name = Path(file.filename or "").name
        if not name or not ws.upload_name_ok(name):
            raise HTTPException(status_code=400, detail="bad filename")
        try:
            from hubv1.archive import ingest_upload

            info = ingest_upload(
                acc,
                workspace_id=mine["workspace_id"],
                name=name,
                fileobj=file.file,
                parent_id=parent_id,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info, status=201)

    @router.get("/nodes/{node_id}")
    def get_node(node_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        node = ws.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="not found")
        w = ws.get_workspace(node["workspace_id"])
        if not w or not ws.can_read_workspace(acc, w):
            raise HTTPException(status_code=404, detail="not found")
        data = dict(node)
        data["writable"] = ws.can_write_workspace(acc, w)
        return envelope(request, data)

    @router.put("/nodes/{node_id}")
    def put_node(node_id: str, body: NodeUpdate, request: Request, acc: Access = Depends(require_api("view"))):
        _reject_spoof(acc, body)
        try:
            if body.body is None:
                raise ValueError("body required")
            info = ws.update_file(
                acc,
                node_id,
                expected_revision=body.expected_revision,
                data=body.body.encode("utf-8"),
                mime=body.mime_type,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=body.admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    @router.delete("/nodes/{node_id}")
    def delete_node(node_id: str, body: NodeRev, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = ws.tombstone(
                acc,
                node_id,
                expected_revision=body.expected_revision,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=body.admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    @router.post("/nodes/{node_id}/move")
    def move_node(node_id: str, body: NodeMove, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = ws.move_node(
                acc,
                node_id,
                parent_id=body.parent_id,
                name=body.name,
                expected_revision=body.expected_revision,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=body.admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    @router.post("/nodes/{node_id}/restore")
    def restore_node(node_id: str, body: NodeRev, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = ws.restore_node(
                acc,
                node_id,
                expected_revision=body.expected_revision,
                request_id=getattr(request.state, "request_id", ""),
                admin_reason=body.admin_reason,
            )
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    @router.get("/nodes/{node_id}/versions")
    def node_versions(node_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        node = ws.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="not found")
        w = ws.get_workspace(node["workspace_id"])
        if not w or not ws.can_read_workspace(acc, w):
            raise HTTPException(status_code=404, detail="not found")
        return envelope(request, {"items": ws.list_versions(node_id)})

    @router.get("/nodes/{node_id}/file")
    def download_node(node_id: str, request: Request, acc: Access = Depends(require_api("view")), version_id: Optional[str] = None):
        node = ws.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="not found")
        w = ws.get_workspace(node["workspace_id"])
        if not w or not ws.can_read_workspace(acc, w):
            raise HTTPException(status_code=404, detail="not found")
        from fastapi.responses import FileResponse
        from urllib.parse import quote

        try:
            path, mime, name = ws.file_disk(node_id, version_id)
        except Exception as exc:
            _http(exc)
        return FileResponse(
            path,
            media_type=mime or "application/octet-stream",
            filename=name,
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/capabilities")
    def get_capabilities(request: Request, acc: Access = Depends(require_api("view"))):
        return envelope(request, ws.capabilities(acc))

    @router.get("/jobs")
    def list_jobs(request: Request, acc: Access = Depends(require_api("view"))):
        with connect() as conn:
            rows = conn.execute(
                "SELECT job_key, status, attempt, updated_at, substr(result,1,200) AS result FROM job_runs ORDER BY updated_at DESC LIMIT 40"
            ).fetchall()
        items = []
        for r in rows:
            blob = dict(r)
            text = json.dumps(blob, ensure_ascii=False)
            if "token" in text.lower() or "secret" in text.lower():
                blob["result"] = "(redacted)"
            items.append(blob)
        return envelope(request, {"items": items, "embedded_scheduler": flag("feature_embedded_scheduler")})

    @router.get("/publish-requests")
    def get_publish_list(request: Request, acc: Access = Depends(require_api("view"))):
        return envelope(request, {"items": publisher.list_requests(acc), "enabled": publisher.publisher_enabled()})

    @router.post("/publish-requests")
    async def post_publish(request: Request, acc: Access = Depends(require_api("view"))):
        _deny_without_publish(acc)
        body = await _json_model(request, PublishIn)
        _reject_spoof(acc, body)
        try:
            info = publisher.create_request(
                acc,
                node_ids=body.node_ids,
                target_owner=body.target_owner,
                repo=body.repo,
                branch=body.branch,
                create_repo=body.create_repo,
                request_id=getattr(request.state, "request_id", ""),
            )
        except Exception as orig:
            _http(orig)
        return envelope(request, info, status=201)

    @router.get("/publish-requests/{request_id}")
    def get_publish(request_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        row = publisher.get_request(request_id)
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        if not acc.manage and row["actor_id"] != acc.p.id:
            raise HTTPException(status_code=404, detail="not found")
        return envelope(request, row)

    @router.post("/publish-requests/{request_id}/approve")
    def approve_publish(request_id: str, request: Request, acc: Access = Depends(require_api("manage"))):
        try:
            info = publisher.decide(acc, request_id, approve=True, request_id_http=getattr(request.state, "request_id", ""))
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    @router.post("/publish-requests/{request_id}/reject")
    def reject_publish(request_id: str, request: Request, acc: Access = Depends(require_api("manage"))):
        try:
            info = publisher.decide(acc, request_id, approve=False, request_id_http=getattr(request.state, "request_id", ""))
        except Exception as exc:
            _http(exc)
        return envelope(request, info)

    for path, fn, methods in (
        ("/workspaces", list_workspaces, ["GET"]),
        ("/workspaces/me", my_workspace, ["GET"]),
        ("/capabilities", get_capabilities, ["GET"]),
    ):
        shared_router.add_api_route(path, fn, methods=methods)
