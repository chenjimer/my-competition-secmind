from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from secmind.ledger import LedgerStore
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AgentState,
    ApprovalResponse,
    BudgetState,
    RunStatus,
    RunSummary,
    TaskRequest,
)


class EventHub:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers.get(str(event["run_id"]), ()))
        for queue in subscribers:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self, run_id: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers[run_id].add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers[run_id].discard(queue)


class RunService:
    def __init__(self, orchestrator: SecMindOrchestrator, ledger: LedgerStore, event_hub: EventHub) -> None:
        self.orchestrator = orchestrator
        self.ledger = ledger
        self.event_hub = event_hub
        self._tasks: set[asyncio.Task[Any]] = set()

    def submit(self, task: TaskRequest) -> str:
        run_id = str(uuid4())
        state = AgentState(
            run_id=run_id,
            task=task,
            status=RunStatus.PENDING,
            budget=BudgetState(
                max_steps=self.orchestrator.settings.max_steps,
                max_tool_calls=self.orchestrator.settings.max_tool_calls,
                max_model_calls=self.orchestrator.settings.max_model_calls,
                max_runtime_seconds=self.orchestrator.settings.max_runtime_seconds,
            ),
        )
        self.ledger.save_state(state)
        self.ledger.append(run_id, "run.queued", {"objective": task.objective}, actor="api")
        self._spawn(self._start(task, run_id))
        return run_id

    async def _start(self, task: TaskRequest, run_id: str) -> None:
        try:
            await self.orchestrator.start(task, run_id)
        except Exception as exc:
            state = self.ledger.load_state(run_id)
            if state is not None:
                state.status = RunStatus.FAILED
                state.last_error = f"{type(exc).__name__}: {exc}"
                self.ledger.save_state(state)
                event = self.ledger.append(run_id, "run.failed", {"error": state.last_error}, actor="orchestrator")
                await self.event_hub.publish(event.model_dump(mode="json"))

    def submit_approval(self, run_id: str, response: ApprovalResponse) -> None:
        if self.ledger.load_state(run_id) is None:
            raise KeyError(run_id)
        self._spawn(self.orchestrator.resume(run_id, response))

    def state(self, run_id: str) -> AgentState:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        return state

    def summary(self, run_id: str) -> RunSummary:
        state = self.state(run_id)
        return RunSummary(
            run_id=run_id,
            status=state.status,
            scenario=state.scenario,
            current_step=state.current_step_index,
            total_steps=len(state.plan),
            pending_approval=state.pending_approval,
            last_error=state.last_error,
        )

    async def recover_incomplete(self) -> None:
        for run_id in self.ledger.incomplete_run_ids():
            state = self.ledger.load_state(run_id)
            if state and state.status not in {RunStatus.PENDING, RunStatus.WAITING_APPROVAL}:
                self._spawn(self.orchestrator.recover(run_id))

    async def shutdown(self) -> None:
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
