"""CLI-facing REST: health/me, two-phase upload, import jobs, publish plans."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from urllib.parse import quote

from hubv1.acl import Access
from hubv1.flags import flag_int
from hubv1.store import WORKSPACE_MAX_FILE_BYTES, connect
from hubv1 import workspace as ws
from hubv1 import xfer


class UploadDecl(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    purpose: str = "file"


class CommitIn(BaseModel):
    upload_id: str
    path: str = Field(min_length=1, max_length=512)
    if_match: str = ""
    if_none_match: bool = False


class PreviewIn(BaseModel):
    upload_id: str
    dest: str = Field(min_length=1, max_length=160)
    root_mapping: str = "keep"


class ImportIn(BaseModel):
    preview_id: str
    manifest_hash: str
    dest: str = ""
    expected_revision: Optional[int] = None
    conflict: str = "fail"


class PlanIn(BaseModel):
    prefix: str = ""
    repo: str = Field(min_length=3, max_length=120)
    mode: str = "create"
    visibility: str = "public"
    license: str = "MIT"
    copyright_holder: str = "sunnyspot114514"
    workspace_id: str = ""


class PlanReqIn(BaseModel):
    plan_id: str
    manifest_hash: str


def _err(request: Request, status: int, code: str, message: str, *, retryable: bool = False, details: Optional[dict] = None) -> JSONResponse:
    rid = getattr(request.state, "request_id", "")
    return JSONResponse(
        {"error": {"code": code, "message": message, "retryable": retryable, "details": details or {}}, "request_id": rid},
        status_code=status,
    )


def _http(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, PermissionError):
        return _err(request, 403, "forbidden", str(exc) or "forbidden")
    if isinstance(exc, KeyError):
        return _err(request, 404, "not_found", "not found")
    if isinstance(exc, FileExistsError):
        return _err(request, 409, "exists", str(exc) or "exists")
    if isinstance(exc, RuntimeError) and str(exc) == "conflict":
        return _err(request, 412, "conflict", "etag or revision conflict")
    if isinstance(exc, OverflowError):
        return _err(request, 413, "too_large", str(exc) or "too large")
    if isinstance(exc, MemoryError):
        return _err(request, 413, "quota", str(exc) or "quota")
    if isinstance(exc, ValueError):
        return _err(request, 422, "invalid", str(exc)[:300])
    raise exc


def attach(router, shared_router, *, require_api, envelope):
    @router.get("/health")
    def api_health():
        ready = True
        try:
            with connect() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception:
            ready = False
        return {"ok": True, "ready": ready}

    @router.get("/me")
    def api_me(request: Request, acc: Access = Depends(require_api("view"))):
        mine = ws.workspace_of(acc.p.id)
        wid = mine["workspace_id"] if mine else None
        return envelope(
            request,
            {
                "identity": acc.p.id,
                "identity_id": acc.p.id,
                "workspace_id": wid,
                "own_workspace_id": wid,
                "scopes": sorted(acc.scopes) if not acc.manage else ["*"],
                "disabled": bool(acc.revoked),
                "roles": sorted(getattr(acc.p, "roles", []) or []),
            },
        )

    @router.post("/uploads")
    def post_upload(body: UploadDecl, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = xfer.create_upload(acc, name=body.name, nbytes=body.bytes, sha256=body.sha256, purpose=body.purpose)
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info, status=201)

    @router.put("/uploads/{upload_id}/content")
    async def put_upload(upload_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        import tempfile

        max_bytes = flag_int("workspace_max_file_bytes", WORKSPACE_MAX_FILE_BYTES)
        spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        try:
            async for chunk in request.stream():
                spool.write(chunk)
            spool.seek(0)
            info = xfer.put_upload_fileobj(acc, upload_id, spool, max_bytes=max_bytes)
            xfer.consume_upload_tickets(upload_id)
        except Exception as exc:
            return _http(request, exc)
        finally:
            spool.close()
        return envelope(request, info)

    @router.post("/workspaces/{workspace_id}/files/commit")
    def commit_file(workspace_id: str, body: CommitIn, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = xfer.commit_file(
                acc,
                workspace_id,
                upload_id=body.upload_id,
                path=body.path,
                if_match=body.if_match,
                if_none_match=body.if_none_match,
            )
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info, status=201)

    @router.get("/workspaces/{workspace_id}/files")
    def list_files(
        workspace_id: str,
        request: Request,
        acc: Access = Depends(require_api("view")),
        cursor: str = "",
        limit: int = 50,
        max_bytes: int = 16384,
    ):
        try:
            info = xfer.list_files_page(acc, workspace_id, cursor=cursor, limit=limit, max_bytes=max_bytes)
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info)

    @router.get("/workspaces/{workspace_id}/files/content")
    def get_file_content(workspace_id: str, request: Request, path: str, acc: Access = Depends(require_api("view"))):
        try:
            disk, mime, name = xfer.file_content(acc, workspace_id, path)
        except Exception as exc:
            return _http(request, exc)
        return FileResponse(
            disk,
            media_type=mime,
            filename=name,
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
                "Cache-Control": "no-store",
            },
        )

    @router.post("/workspaces/{workspace_id}/imports/preview")
    def preview_import(workspace_id: str, body: PreviewIn, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = xfer.preview_import(acc, workspace_id, upload_id=body.upload_id, dest=body.dest)
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info)

    @router.post("/workspaces/{workspace_id}/imports")
    def post_import(workspace_id: str, body: ImportIn, request: Request, acc: Access = Depends(require_api("view"))):
        key = (request.headers.get("idempotency-key") or "").strip()
        req_hash = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).hexdigest()
        if key:
            prev = xfer.get_op(acc, key)
            if prev:
                if prev["request_hash"] != req_hash:
                    return _err(request, 409, "idempotency_conflict", "idempotency conflict")
                return JSONResponse(json.loads(prev["response"]), status_code=int(prev["status_code"]))
        try:
            info = xfer.run_import(
                acc,
                workspace_id,
                preview_id=body.preview_id,
                manifest_hash=body.manifest_hash,
                conflict=body.conflict or "fail",
                expected_revision=body.expected_revision,
            )
        except Exception as exc:
            return _http(request, exc)
        payload = {
            "schema_version": "1.3.0",
            "request_id": getattr(request.state, "request_id", ""),
            "data": {"job_id": info["job_id"], "state": info["state"], "result": info.get("result")},
            "cursor": None,
            "stale": False,
            "omitted": 0,
        }
        if key:
            xfer.remember_op(acc, key, "POST", str(request.url.path), req_hash, 202, payload, job_id=info["job_id"])
        return JSONResponse(payload, status_code=202)

    @router.get("/jobs/{job_id}")
    def get_job(job_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        try:
            info = xfer.get_job(acc, job_id)
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info)

    @router.get("/operations/{key}")
    def get_op(key: str, request: Request, acc: Access = Depends(require_api("view"))):
        row = xfer.get_op(acc, key)
        if not row:
            return _err(request, 404, "not_found", "not found")
        return envelope(request, {"key": key, "status_code": row["status_code"], "job_id": row.get("job_id")})

    @router.post("/publish/plans")
    async def post_plan(request: Request, acc: Access = Depends(require_api("view"))):
        from fastapi.exceptions import RequestValidationError
        from pydantic import ValidationError
        from hubv1 import publisher

        if not publisher.actor_can_request(acc):
            return _err(request, 403, "forbidden", "forbidden")
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        try:
            body = PlanIn.model_validate(payload)
        except ValidationError as orig:
            raise RequestValidationError(orig.errors())
        mine = ws.workspace_of(acc.p.id)
        wid = body.workspace_id or (mine["workspace_id"] if mine else "")
        try:
            info = xfer.create_plan(
                acc,
                wid,
                prefix=body.prefix,
                repo=body.repo,
                mode=body.mode,
                visibility=body.visibility,
                license_id=body.license,
                copyright_holder=body.copyright_holder,
            )
        except Exception as exc:
            return _http(request, exc)
        return envelope(request, info, status=201)

    @router.post("/publish/requests")
    async def post_plan_request(request: Request, acc: Access = Depends(require_api("view"))):
        from fastapi.exceptions import RequestValidationError
        from pydantic import ValidationError
        from hubv1 import publisher

        if not publisher.actor_can_request(acc):
            return _err(request, 403, "forbidden", "forbidden")
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        try:
            body = PlanReqIn.model_validate(payload)
        except ValidationError as orig:
            raise RequestValidationError(orig.errors())
        try:
            info = xfer.request_from_plan(
                acc,
                plan_id=body.plan_id,
                manifest_hash=body.manifest_hash,
                request_id=getattr(request.state, "request_id", ""),
            )
        except Exception as orig:
            return _http(request, orig)
        return envelope(request, info, status=201)

    @router.get("/publish/requests/{request_id}")
    def get_plan_request(request_id: str, request: Request, acc: Access = Depends(require_api("view"))):
        from hubv1 import publisher

        row = publisher.get_request(request_id)
        if not row:
            return _err(request, 404, "not_found", "not found")
        if not acc.manage and row["actor_id"] != acc.p.id:
            return _err(request, 404, "not_found", "not found")
        return envelope(request, row)

    shared_router.add_api_route("/health", api_health, methods=["GET"])
    shared_router.add_api_route("/me", api_me, methods=["GET"])
    shared_router.add_api_route("/uploads", post_upload, methods=["POST"])
    shared_router.add_api_route("/jobs/{job_id}", get_job, methods=["GET"])
    shared_router.add_api_route("/operations/{key}", get_op, methods=["GET"])
    shared_router.add_api_route("/publish/plans", post_plan, methods=["POST"])
    shared_router.add_api_route("/publish/requests", post_plan_request, methods=["POST"])
    shared_router.add_api_route("/publish/requests/{request_id}", get_plan_request, methods=["GET"])
