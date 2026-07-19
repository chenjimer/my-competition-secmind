from __future__ import annotations

import inspect
import json
import time as time_module
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict, cast
from uuid import uuid4

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from secmind.agents import (
    AnalystAgent,
    PlannerAgent,
    ReporterAgent,
    TaskInterpreterAgent,
    VerifierAgent,
)
from secmind.config import Settings
from secmind.guardrail import GuardrailAction
from secmind.ingest import IngestError, InputIngestor
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.memory import QdrantVectorStore
from secmind.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    BudgetState,
    DecisionRecord,
    RunStatus,
    TaskRequest,
    ToolContext,
    ToolStatus,
)
from secmind.tools import ToolBroker


class GraphState(TypedDict, total=False):
    agent: dict[str, Any]
    route: str


Publisher = Callable[[dict[str, Any]], Awaitable[None] | None]


class SecMindOrchestrator:
    def __init__(
        self,
        settings: Settings,
        ledger: LedgerStore,
        gateway: QwenGateway,
        broker: ToolBroker,
        publisher: Publisher | None = None,
        memory_store: QdrantVectorStore | None = None,
    ) -> None:
        self.settings = settings
        self.ledger = ledger
        self.gateway = gateway
        self.broker = broker
        self.publisher = publisher
        self.ingestor = InputIngestor(settings)
        self.interpreter = TaskInterpreterAgent(gateway)
        self.planner = PlannerAgent(gateway)
        self.analyst = AnalystAgent(gateway)
        self.verifier = VerifierAgent(gateway)
        self.reporter = ReporterAgent(gateway)
        self.memory_store = memory_store
        self.checkpointer = InMemorySaver()
        self.graph = self._build_graph().compile(checkpointer=self.checkpointer)

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(GraphState)
        nodes = {
            "ingest": self._ingest,
            "classify": self._classify,
            "retrieve_context": self._retrieve_context,
            "plan": self._plan,
            "validate_plan": self._validate_plan,
            "select_step": self._select_step,
            "guardrail": self._guardrail,
            "approval": self._approval,
            "record_denial": self._record_denial,
            "execute": self._execute,
            "observe": self._observe,
            "analyze": self._analyze,
            "verify": self._verify,
            "reflect": self._reflect,
            "report": self._report,
            "memory_commit": self._memory_commit,
        }
        # LangGraph's callable protocol stubs do not currently accept bound async methods,
        # although these signatures are supported by the runtime.
        for name, node in nodes.items():
            graph.add_node(name, cast(Any, node))

        graph.add_edge(START, "ingest")
        graph.add_edge("ingest", "classify")
        graph.add_edge("classify", "retrieve_context")
        graph.add_edge("retrieve_context", "plan")
        graph.add_edge("plan", "validate_plan")
        graph.add_conditional_edges(
            "validate_plan",
            lambda value: value.get("route", "select"),
            {"select": "select_step", "report": "report"},
        )
        graph.add_conditional_edges(
            "select_step",
            lambda value: value.get("route", "guardrail"),
            {"guardrail": "guardrail", "report": "report"},
        )
        graph.add_conditional_edges(
            "guardrail",
            lambda value: value.get("route", "execute"),
            {"execute": "execute", "approval": "approval", "deny": "record_denial"},
        )
        graph.add_conditional_edges(
            "approval",
            lambda value: value.get("route", "execute"),
            {"execute": "execute", "deny": "record_denial"},
        )
        graph.add_edge("record_denial", "report")
        graph.add_edge("execute", "observe")
        graph.add_edge("observe", "analyze")
        graph.add_edge("analyze", "verify")
        graph.add_conditional_edges(
            "verify",
            lambda value: value.get("route", "report"),
            {"next": "select_step", "reflect": "reflect", "report": "report"},
        )
        graph.add_edge("reflect", "select_step")
        graph.add_edge("report", "memory_commit")
        graph.add_edge("memory_commit", END)
        return graph

    async def start(self, task: TaskRequest, run_id: str | None = None) -> AgentState:
        actual_run_id = run_id or str(uuid4())
        state = AgentState(
            run_id=actual_run_id,
            task=task,
            budget=BudgetState(
                max_steps=self.settings.max_steps,
                max_tool_calls=self.settings.max_tool_calls,
                max_model_calls=self.settings.max_model_calls,
                max_runtime_seconds=self.settings.max_runtime_seconds,
            ),
        )
        self.ledger.save_state(state)
        await self._event(state, "run.created", {"objective": task.objective})
        return await self._invoke({"agent": state.model_dump(mode="json")}, actual_run_id)

    async def resume(self, run_id: str, response: ApprovalResponse) -> AgentState:
        config = {"configurable": {"thread_id": run_id}}
        try:
            result = await self.graph.ainvoke(Command(resume=response.model_dump(mode="json")), cast(Any, config))
            return self._state(cast(GraphState, result))
        except Exception:
            # After a process restart the in-memory LangGraph checkpoint is gone. The durable
            # snapshot is safely replayed; currently enabled tools are idempotent/read-only.
            state = self.ledger.load_state(run_id)
            if state is None or state.pending_approval is None:
                raise
            state.approvals.append(
                {
                    "request_id": state.pending_approval.request_id,
                    "step_id": state.pending_approval.step_id,
                    **response.model_dump(mode="json"),
                }
            )
            if response.decision == ApprovalDecision.DENY:
                state.status = RunStatus.DENIED
            elif response.decision == ApprovalDecision.EDIT and response.edited_parameters is not None:
                state.plan[state.current_step_index].inputs = response.edited_parameters
                state.status = RunStatus.RUNNING
            else:
                state.status = RunStatus.RUNNING
            state.pending_approval = None
            self.ledger.save_state(state)
            await self._event(state, "approval.recovered", response.model_dump(mode="json"))
            return await self._invoke({"agent": state.model_dump(mode="json")}, run_id)

    async def recover(self, run_id: str) -> AgentState:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        if state.status == RunStatus.WAITING_APPROVAL:
            return state
        return await self._invoke({"agent": state.model_dump(mode="json")}, run_id)

    async def _invoke(self, input_value: GraphState | Command, run_id: str) -> AgentState:
        result = await self.graph.ainvoke(
            input_value,
            {"configurable": {"thread_id": run_id}, "recursion_limit": self.settings.max_steps * 4},
        )
        state = self._state(cast(GraphState, result))
        self.ledger.save_state(state)
        return state

    @staticmethod
    def _state(value: GraphState) -> AgentState:
        return AgentState.model_validate(value["agent"])

    async def _checkpoint(
        self, state: AgentState, event_type: str, payload: dict[str, Any], route: str | None = None
    ) -> GraphState:
        self.ledger.save_state(state)
        await self._event(state, event_type, payload)
        result: GraphState = {"agent": state.model_dump(mode="json")}
        if route is not None:
            result["route"] = route
        return result

    async def _event(self, state: AgentState, event_type: str, payload: dict[str, Any]) -> None:
        event = self.ledger.append(state.run_id, event_type, payload)
        if self.publisher is not None:
            result = self.publisher(event.model_dump(mode="json"))
            if inspect.isawaitable(result):
                await result

    async def _ingest(self, value: GraphState) -> GraphState:
        state = self._state(value)
        state.status = RunStatus.RUNNING
        if not state.workspace:
            try:
                workspace, artifacts = self.ingestor.ingest(state.run_id, state.task.attachments)
                state.workspace = str(workspace)
                state.input_artifacts = artifacts
            except IngestError as exc:
                state.status = RunStatus.FAILED
                state.last_error = str(exc)
        return await self._checkpoint(
            state,
            "input.ingested",
            {
                "artifact_count": len(state.input_artifacts),
                "artifact_hashes": [item.sha256 for item in state.input_artifacts],
                "error": state.last_error,
            },
        )

    async def _classify(self, value: GraphState) -> GraphState:
        state = await self.interpreter.run(self._state(value))
        return await self._checkpoint(state, "scenario.classified", {"scenario": state.scenario})

    async def _retrieve_context(self, value: GraphState) -> GraphState:
        state = self._state(value)
        hit_count = 0
        query_start = time_module.monotonic()

        if self.memory_store is not None:
            query_parts = [state.task.objective]
            if state.scenario:
                query_parts.append(str(state.scenario))
            if state.task.target_scope:
                query_parts.append(", ".join(state.task.target_scope))
            query_text = " ".join(query_parts)
            embedding_model = ""

            try:
                if not self.settings.demo_mode and self.settings.qwen_api_key:
                    vectors = await self.gateway.embeddings([query_text])
                    query_vector = vectors[0]
                    embedding_model = self.settings.embedding_model
                else:
                    import random
                    query_vector = [random.random() for _ in range(self.memory_store.vector_size)]
                    embedding_model = "random-fallback"

                hits = self.memory_store.search(query_vector, top_k=5)
                state.knowledge_hits = hits
                hit_count = len(hits)
                query_duration = int((time_module.monotonic() - query_start) * 1000)

                # 留存查询记录
                try:
                    hits_data = [
                        {
                            "memory_id": h.memory_id,
                            "content": h.content,
                            "source": h.source,
                            "version": h.version,
                            "confidence": h.confidence,
                            "metadata": h.metadata,
                        }
                        for h in hits
                    ]
                    self.ledger.log_query(
                        query_text=query_text,
                        hits_json=json.dumps(hits_data, ensure_ascii=False),
                        hit_count=hit_count,
                        run_id=state.run_id,
                        query_vector_json=json.dumps(query_vector) if not self.settings.demo_mode else None,
                        top_k=5,
                        embedding_model=embedding_model,
                        duration_ms=query_duration,
                    )
                except Exception:
                    pass  # 查询日志不应影响主流程

                state.decisions.append(
                    DecisionRecord(
                        decision="knowledge_retrieved",
                        rationale_summary=f"Retrieved {hit_count} ATT&CK knowledge entries for: {query_text[:80]}",
                        policy_ids=["RAG-CITATION-V1"],
                        model_id="deterministic-retriever",
                    )
                )
            except Exception as exc:
                state.decisions.append(
                    DecisionRecord(
                        decision="knowledge_retrieval_failed",
                        rationale_summary=f"Knowledge retrieval error: {exc}",
                        policy_ids=["RAG-CITATION-V1"],
                        model_id="deterministic-retriever",
                    )
                )
        else:
            state.decisions.append(
                DecisionRecord(
                    decision="knowledge_context_empty",
                    rationale_summary="No external knowledge was required for the deterministic Bandit baseline.",
                    policy_ids=["RAG-CITATION-V1"],
                    model_id="deterministic-retriever",
                )
            )

        return await self._checkpoint(state, "knowledge.retrieved", {"hit_count": hit_count})

    async def _plan(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if not state.plan:
            state = await self.planner.run(state)
        return await self._checkpoint(
            state, "plan.created", {"steps": [item.model_dump(mode="json") for item in state.plan]}
        )

    async def _validate_plan(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.status == RunStatus.FAILED:
            return await self._checkpoint(state, "plan.skipped", {"reason": state.last_error}, "report")
        errors: list[str] = []
        identifiers = [step.step_id for step in state.plan]
        if len(identifiers) != len(set(identifiers)):
            errors.append("Plan step identifiers must be unique")
        if len(state.plan) > state.budget.max_steps:
            errors.append("Plan exceeds step budget")
        known_tools = {item.name for item in self.broker.registry.manifests()}
        for step in state.plan:
            if not set(step.dependencies).issubset(set(identifiers)):
                errors.append(f"Unknown dependency in {step.step_id}")
            if not set(step.tool_candidates).issubset(known_tools):
                errors.append(f"Unknown tool in {step.step_id}")
        if errors:
            state.status = RunStatus.FAILED
            state.last_error = "; ".join(errors)
        route = "select" if state.plan and not errors else "report"
        return await self._checkpoint(state, "plan.validated", {"errors": errors}, route)

    async def _select_step(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.current_step_index >= len(state.plan):
            return await self._checkpoint(state, "step.selection_complete", {}, "report")
        if state.budget.steps_used >= state.budget.max_steps:
            state.status = RunStatus.PARTIAL
            state.last_error = "Step budget exhausted"
            return await self._checkpoint(state, "budget.exhausted", {"budget": "steps"}, "report")
        state.budget.steps_used += 1
        step = state.plan[state.current_step_index]
        return await self._checkpoint(
            state, "step.selected", {"step_id": step.step_id, "index": state.current_step_index}, "guardrail"
        )

    async def _guardrail(self, value: GraphState) -> GraphState:
        state = self._state(value)
        step = state.plan[state.current_step_index]
        if not step.tool_candidates:
            state.status = RunStatus.FAILED
            state.last_error = "Selected step has no tool candidate"
            return await self._checkpoint(state, "guardrail.denied", {"reason": state.last_error}, "deny")
        tool_name = step.tool_candidates[0]
        approved = next(
            (
                item
                for item in reversed(state.approvals)
                if item.get("step_id") == step.step_id
                and item.get("decision") in {ApprovalDecision.APPROVE.value, ApprovalDecision.EDIT.value}
            ),
            None,
        )
        decision = self.broker.assess(tool_name, step.inputs, state.task.autonomy_policy)
        state.decisions.append(
            DecisionRecord(
                decision=f"guardrail={decision.action.value}",
                rationale_summary=decision.reason,
                policy_ids=list(decision.policy_ids),
                model_id="deterministic-guardrail",
            )
        )
        if decision.action == GuardrailAction.DENY:
            state.status = RunStatus.DENIED
            route = "deny"
        elif decision.action == GuardrailAction.REQUIRE_APPROVAL and approved is None:
            state.status = RunStatus.WAITING_APPROVAL
            state.pending_approval = ApprovalRequest(
                run_id=state.run_id,
                step_id=step.step_id,
                tool_name=tool_name,
                parameters=step.inputs,
                target=str(step.inputs.get("target", state.workspace)),
                risk_level=decision.risk_level,
                reason=decision.reason,
                expected_impact="Execute one bounded tool call inside the controlled workspace.",
            )
            route = "approval"
        else:
            route = "execute"
        return await self._checkpoint(
            state,
            "guardrail.evaluated",
            {
                "step_id": step.step_id,
                "action": decision.action,
                "risk_level": decision.risk_level,
                "policy_ids": decision.policy_ids,
            },
            route,
        )

    async def _approval(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.pending_approval is None:
            state.status = RunStatus.FAILED
            state.last_error = "Approval node entered without a pending request"
            return await self._checkpoint(state, "approval.invalid", {}, "deny")
        self.ledger.save_state(state)
        await self._event(state, "approval.requested", state.pending_approval.model_dump(mode="json"))
        raw_response = interrupt(state.pending_approval.model_dump(mode="json"))
        response = ApprovalResponse.model_validate(raw_response)
        pending = state.pending_approval
        state.approvals.append(
            {
                "request_id": pending.request_id,
                "step_id": pending.step_id,
                **response.model_dump(mode="json"),
            }
        )
        state.pending_approval = None
        if response.decision == ApprovalDecision.DENY:
            state.status = RunStatus.DENIED
            route = "deny"
        else:
            if response.decision == ApprovalDecision.EDIT and response.edited_parameters is not None:
                state.plan[state.current_step_index].inputs = response.edited_parameters
            state.status = RunStatus.RUNNING
            route = "execute"
        return await self._checkpoint(state, "approval.resolved", response.model_dump(mode="json"), route)

    async def _record_denial(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.status != RunStatus.FAILED:
            state.status = RunStatus.DENIED
        return await self._checkpoint(
            state, "step.denied", {"step_index": state.current_step_index, "error": state.last_error}
        )

    async def _execute(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.budget.tool_calls_used >= state.budget.max_tool_calls:
            state.status = RunStatus.PARTIAL
            state.last_error = "Tool-call budget exhausted"
            return await self._checkpoint(state, "budget.exhausted", {"budget": "tools"})
        step = state.plan[state.current_step_index]
        tool_name = step.tool_candidates[0]
        state.budget.tool_calls_used += 1
        await self._event(
            state,
            "tool.started",
            {
                "tool": tool_name,
                "tool_version": self.broker.registry.get(tool_name).manifest.version,
                "args": step.inputs,
            },
        )
        result = await self.broker.invoke(
            tool_name,
            step.inputs,
            ToolContext(
                run_id=state.run_id,
                step_id=step.step_id,
                workspace=state.workspace,
                allowed_paths=[state.workspace],
            ),
        )
        state.observations.append(result)
        return await self._checkpoint(
            state,
            "tool.completed",
            {
                "tool": tool_name,
                "status": result.status,
                "duration_ms": result.duration_ms,
                "evidence_ids": [item.evidence_id for item in result.evidence],
                "error_code": result.error_code,
            },
        )

    async def _observe(self, value: GraphState) -> GraphState:
        state = self._state(value)
        latest = state.observations[-1]
        return await self._checkpoint(
            state, "observation.recorded", {"status": latest.status, "summary": latest.summary}
        )

    async def _analyze(self, value: GraphState) -> GraphState:
        state = await self.analyst.run(self._state(value))
        return await self._checkpoint(
            state,
            "analysis.completed",
            {"finding_count": len(state.findings), "evidence_count": len(state.evidence)},
        )

    async def _verify(self, value: GraphState) -> GraphState:
        state = await self.verifier.run(self._state(value))
        step = state.plan[state.current_step_index]
        latest = state.observations[-1]
        if latest.status == ToolStatus.SUCCESS and state.last_error is None:
            state.current_step_index += 1
            route = "next" if state.current_step_index < len(state.plan) else "report"
        else:
            attempts = state.retry_counts.get(step.step_id, 0)
            if attempts + 1 < step.max_attempts and state.budget.steps_used < state.budget.max_steps:
                route = "reflect"
            else:
                state.status = RunStatus.PARTIAL
                route = "report"
        return await self._checkpoint(
            state,
            "verification.completed",
            {"step_id": step.step_id, "route": route, "error": state.last_error},
            route,
        )

    async def _reflect(self, value: GraphState) -> GraphState:
        state = self._state(value)
        step = state.plan[state.current_step_index]
        state.retry_counts[step.step_id] = state.retry_counts.get(step.step_id, 0) + 1
        state.last_error = None
        state.decisions.append(
            DecisionRecord(
                decision="retry_step",
                rationale_summary="The bounded tool call failed and has a remaining retry allowance.",
                policy_ids=["RETRY-IDEMPOTENT-V1"],
                model_id="deterministic-reflector",
            )
        )
        return await self._checkpoint(
            state, "reflection.completed", {"step_id": step.step_id, "retry": state.retry_counts[step.step_id]}
        )

    async def _report(self, value: GraphState) -> GraphState:
        state = await self.reporter.run(self._state(value))
        payload = {
            "status": state.status,
            "finding_count": len(state.findings),
            "evidence_count": len(state.evidence),
        }
        return await self._checkpoint(state, "report.generated", payload)

    async def _memory_commit(self, value: GraphState) -> GraphState:
        state = self._state(value)
        accepted = state.status == RunStatus.COMPLETED and state.report is not None
        payload = {
            "accepted": accepted,
            "reason": "Verified completed runs are eligible for episodic-memory curation."
            if accepted
            else "Only verified completed runs may enter long-term memory.",
        }
        return await self._checkpoint(state, "memory.candidate", payload)
