from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from secmind.config import Settings, get_settings
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway, close_gateway_safely
from secmind.memory import QdrantVectorStore
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import ApprovalResponse, RunStatus, TaskRequest
from secmind.service import EventHub, RunService
from secmind.tools import ToolBroker, default_registry


def build_runtime(settings: Settings) -> tuple[RunService, QwenGateway]:
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    hub = EventHub()
    gateway = QwenGateway(settings)
    broker = ToolBroker(default_registry(), Guardrail())
    qdrant_url = settings.qdrant_url.replace("qdrant:6333", "localhost:6333")
    memory_store = QdrantVectorStore(
        url=qdrant_url,
        collection_name=settings.qdrant_collection,
        vector_size=settings.qdrant_vector_size,
    )
    orchestrator = SecMindOrchestrator(
        settings, ledger, gateway, broker, hub.publish, memory_store=memory_store
    )
    return RunService(orchestrator, ledger, hub), gateway


def create_app(settings: Settings | None = None) -> FastAPI:
    actual_settings = settings or get_settings()
    service, gateway = build_runtime(actual_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await service.recover_incomplete()
        yield
        await service.shutdown()
        await close_gateway_safely(gateway)

    app = FastAPI(
        title="SecMind Agent API",
        version="0.1.0",
        description="Auditable and recoverable network-security agent runtime.",
        lifespan=lifespan,
    )
    app.state.service = service
    app.state.settings = actual_settings

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "schema_version": "1.0",
            "demo_mode": actual_settings.demo_mode,
        }

    @app.post("/api/v1/uploads", status_code=201)
    async def upload(file: Annotated[UploadFile, File(...)]) -> dict[str, Any]:
        safe_name = Path(file.filename or "upload.bin").name
        if not safe_name or safe_name in {".", ".."}:
            raise HTTPException(400, "Invalid filename")
        reference = f"{uuid4()}-{safe_name}"
        destination = actual_settings.upload_root / reference
        total = 0
        try:
            with destination.open("wb") as stream:
                while chunk := await file.read(1024 * 1024):
                    total += len(chunk)
                    if total > actual_settings.max_upload_bytes:
                        raise HTTPException(413, "Upload exceeds configured size limit")
                    stream.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return {"schema_version": "1.0", "ref": reference, "name": safe_name, "size_bytes": total}

    @app.post("/api/v1/tasks", status_code=202)
    async def create_task(task: TaskRequest) -> dict[str, Any]:
        run_id = service.submit(task)
        return {"schema_version": "1.0", "run_id": run_id, "status": RunStatus.PENDING}

    @app.get("/api/v1/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        try:
            return service.summary(run_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc

    @app.get("/api/v1/runs/{run_id}/report")
    async def get_report(run_id: str) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.report is None:
            raise HTTPException(409, "Report is not available yet")
        return state.report.model_dump(mode="json")

    @app.get("/api/v1/runs/{run_id}/ledger")
    async def get_ledger(
        run_id: str,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        events = service.ledger.events(run_id, after_sequence, limit)
        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "events": [event.model_dump(mode="json") for event in events],
            "chain_valid": service.ledger.verify(run_id),
        }

    @app.get("/api/v1/runs/{run_id}/ledger/export", response_class=FileResponse)
    async def export_ledger(run_id: str) -> FileResponse:
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "Run not found")
        destination = actual_settings.run_root / run_id / "ledger.jsonl"
        service.ledger.export_jsonl(run_id, destination)
        return FileResponse(destination, filename=f"{run_id}-ledger.jsonl")

    @app.post("/api/v1/runs/{run_id}/approvals/{request_id}", status_code=202)
    async def resolve_approval(run_id: str, request_id: str, response: ApprovalResponse) -> dict[str, Any]:
        try:
            state = service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if state.pending_approval is None or state.pending_approval.request_id != request_id:
            raise HTTPException(409, "Approval request is not active")
        service.submit_approval(run_id, response)
        return {"schema_version": "1.0", "run_id": run_id, "accepted": True}

    @app.get("/api/v1/query-logs")
    async def get_query_logs(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """返回知识检索的查询日志记录，每一条包含问题和结果。"""
        logs = service.ledger.query_logs(limit=limit, run_id=run_id)
        return {
            "schema_version": "1.0",
            "total": len(logs),
            "logs": logs,
        }

    @app.websocket("/api/v1/runs/{run_id}/events")
    async def events_socket(websocket: WebSocket, run_id: str, after_sequence: int = 0) -> None:
        if service.ledger.load_state(run_id) is None:
            await websocket.close(code=4404, reason="Run not found")
            return
        await websocket.accept()
        try:
            for stored_event in service.ledger.events(run_id, after_sequence=after_sequence):
                await websocket.send_text(stored_event.model_dump_json())
            async with service.event_hub.subscribe(run_id) as queue:
                while True:
                    live_event = await queue.get()
                    await websocket.send_text(json.dumps(live_event, ensure_ascii=False))
        except WebSocketDisconnect:
            return

    return app


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "secmind.api:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
