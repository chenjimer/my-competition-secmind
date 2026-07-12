from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from secmind.llm import QwenGateway
from secmind.schemas import (
    AgentReport,
    AgentState,
    DecisionRecord,
    Finding,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    ToolStatus,
)


class PlanOutput(BaseModel):
    steps: list[PlanStep]
    rationale_summary: str


class BaseAgent(ABC):
    """Base class for bounded specialist nodes controlled by the orchestrator."""

    name: str
    model_role: str = "worker"
    prompt_version: str = "v1"
    max_react_rounds: int = 3

    def __init__(self, gateway: QwenGateway) -> None:
        self.gateway = gateway

    @abstractmethod
    async def run(self, state: AgentState) -> AgentState:
        raise NotImplementedError


class TaskInterpreterAgent(BaseAgent):
    name = "task_interpreter"

    async def run(self, state: AgentState) -> AgentState:
        text = " ".join([state.task.objective, *state.task.expected_outputs, *state.task.constraints]).lower()
        suffixes = {artifact.relative_path.rsplit(".", 1)[-1].lower() for artifact in state.input_artifacts}
        if any(term in text for term in ("代码", "audit", "code", "漏洞", "bandit")) or "py" in suffixes:
            scenario = Scenario.CODE_AUDIT
        elif any(term in text for term in ("日志", "log")):
            scenario = Scenario.LOG_ANALYSIS
        elif any(term in text for term in ("应急", "incident")):
            scenario = Scenario.INCIDENT_RESPONSE
        elif any(term in text for term in ("渗透", "penetration")):
            scenario = Scenario.PENETRATION_TEST
        else:
            scenario = Scenario.UNKNOWN
        state.scenario = scenario
        state.decisions.append(
            DecisionRecord(
                decision=f"scenario={scenario.value}",
                rationale_summary="Scenario selected from the operator objective and immutable input inventory.",
                policy_ids=["ROUTE-SCENARIO-V1"],
                model_id="deterministic-router",
                prompt_version=self.prompt_version,
            )
        )
        return state


class PlannerAgent(BaseAgent):
    name = "planner"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        if state.scenario != Scenario.CODE_AUDIT:
            state.plan = []
            state.decisions.append(
                DecisionRecord(
                    decision="no_supported_plan",
                    rationale_summary="Only the code-audit scenario is enabled in the first executable baseline.",
                    policy_ids=["SCOPE-MVP-CODE-AUDIT"],
                    model_id="deterministic-planner",
                    prompt_version=self.prompt_version,
                )
            )
            return state
        default = PlanOutput(
            steps=[
                PlanStep(
                    step_id="audit-python-bandit",
                    objective="Scan the controlled workspace for Python security weaknesses.",
                    agent_role="executor",
                    tool_candidates=["bandit_python_audit"],
                    inputs={"target": "."},
                    success_criteria=[
                        "Bandit returns a valid structured result",
                        "Every reported finding has an evidence reference",
                    ],
                    risk_hint=RiskLevel.R1,
                    max_attempts=2,
                )
            ],
            rationale_summary="Static, read-only analysis is the safest reproducible first strategy.",
        )
        if not self.gateway.settings.demo_mode:
            prompt = (
                "Create a bounded code-audit plan. Only use the tool bandit_python_audit. "
                "Do not include hidden reasoning; provide a short rationale summary.\n"
                f"Objective: {state.task.objective}\n"
                f"Inputs: {[item.relative_path for item in state.input_artifacts]}"
            )
            try:
                output, meta = await self.gateway.structured(
                    role=self.model_role,
                    system_prompt="You are SecMind Planner. Return only schema-valid JSON.",
                    user_prompt=prompt,
                    output_model=PlanOutput,
                    prompt_version=self.prompt_version,
                )
                state.budget.model_calls_used += 1
                default = output
                model_id = meta.model_id
            except Exception as exc:  # deterministic degradation is intentional
                model_id = "deterministic-planner-fallback"
                state.last_error = f"Planner model degraded safely: {type(exc).__name__}"
        else:
            model_id = "deterministic-planner"
        state.plan = default.steps
        state.decisions.append(
            DecisionRecord(
                decision="plan_created",
                rationale_summary=default.rationale_summary,
                policy_ids=["PLAN-BOUNDED-V1"],
                model_id=model_id,
                prompt_version=self.prompt_version,
            )
        )
        return state


class AnalystAgent(BaseAgent):
    name = "analyst"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        if not state.observations:
            return state
        latest = state.observations[-1]
        if latest.status == ToolStatus.SUCCESS:
            state.evidence.extend(latest.evidence)
            for item in latest.data.get("findings", []):
                state.findings.append(Finding.model_validate(item))
            state.decisions.append(
                DecisionRecord(
                    decision="tool_result_normalized",
                    rationale_summary=latest.summary,
                    evidence_ids=[item.evidence_id for item in latest.evidence],
                    policy_ids=["EVIDENCE-REQUIRED-V1"],
                    model_id="deterministic-evidence-analyzer",
                )
            )
        return state


class VerifierAgent(BaseAgent):
    name = "verifier"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        orphaned = [finding.finding_id for finding in state.findings if not finding.evidence_ids]
        evidence_ids = {evidence.evidence_id for evidence in state.evidence}
        broken = [
            finding.finding_id
            for finding in state.findings
            if any(reference not in evidence_ids for reference in finding.evidence_ids)
        ]
        if orphaned or broken:
            state.last_error = "Verifier rejected findings with missing or broken evidence references"
            state.decisions.append(
                DecisionRecord(
                    decision="verification_failed",
                    rationale_summary=state.last_error,
                    policy_ids=["EVIDENCE-REQUIRED-V1"],
                    confidence=1,
                )
            )
        else:
            state.decisions.append(
                DecisionRecord(
                    decision="verification_passed",
                    rationale_summary="All normalized findings reference captured tool evidence.",
                    evidence_ids=sorted(evidence_ids),
                    policy_ids=["EVIDENCE-REQUIRED-V1"],
                    confidence=1,
                )
            )
        return state


class ReporterAgent(BaseAgent):
    name = "reporter"
    model_role = "planner"

    async def run(self, state: AgentState) -> AgentState:
        successful = any(item.status == ToolStatus.SUCCESS for item in state.observations)
        if state.status in {RunStatus.DENIED, RunStatus.FAILED}:
            final_status = state.status
        elif state.scenario != Scenario.CODE_AUDIT or not successful:
            final_status = RunStatus.PARTIAL
        else:
            final_status = RunStatus.COMPLETED
        limitations: list[str] = []
        if state.scenario != Scenario.CODE_AUDIT:
            limitations.append("The selected scenario is not enabled in the MVP tool chain.")
        if not state.input_artifacts:
            limitations.append("No input artifacts were supplied; the workspace may contain no analyzable code.")
        if state.last_error:
            limitations.append(state.last_error)
        if successful:
            summary = (
                f"Code audit completed with {len(state.findings)} finding(s), "
                f"supported by {len(state.evidence)} evidence record(s)."
            )
        else:
            summary = "The task ended without a successful security-tool observation."
        state.status = final_status
        state.report = AgentReport(
            run_id=state.run_id,
            status=final_status,
            executive_summary=summary,
            findings=state.findings,
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=limitations,
        )
        return state
