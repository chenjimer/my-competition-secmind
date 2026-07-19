from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from secmind.llm import QwenGateway
from secmind.schemas import (
    AgentReport,
    AgentState,
    DecisionRecord,
    Finding,
    KnowledgeHit,
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

    @staticmethod
    def _build_knowledge_context(state: AgentState) -> str:
        """Format ATT&CK knowledge hits into a plain-text context block for the planner prompt."""
        if not state.knowledge_hits:
            return ""
        lines: list[str] = []
        for hit in state.knowledge_hits:
            attack_id = hit.metadata.get("attack_id", "")
            name = hit.metadata.get("technique_name", "")
            desc = hit.content[:300].replace("\n", " ")  # 截断长内容
            lines.append(f"- {attack_id} {name}: {desc}")
        return "\n".join(lines)

    async def run(self, state: AgentState) -> AgentState:
        default = self._create_default_plan(state)

        if default is None:
            state.plan = []
            state.decisions.append(
                DecisionRecord(
                    decision="no_supported_plan",
                    rationale_summary="Scenario not yet supported.",
                    policy_ids=["SCOPE-CURRENT"],
                    model_id="deterministic-planner",
                    prompt_version=self.prompt_version,
                )
            )
            return state

        if not self.gateway.settings.demo_mode:
            knowledge_ctx = self._build_knowledge_context(state)
            system_prompt = "You are SecMind Planner. Return only schema-valid JSON."
            if knowledge_ctx:
                system_prompt += (
                    "\n\nRelevant ATT&CK knowledge for context:\n"
                    f"{knowledge_ctx}\n\n"
                    "Use this knowledge to inform the plan steps where applicable."
                )
            prompt = (
                f"Create a bounded {state.scenario.value} plan. "
                f"Do not include hidden reasoning; provide a short rationale summary.\n"
                f"Objective: {state.task.objective}\n"
                f"Inputs: {[item.relative_path for item in state.input_artifacts]}"
            )
            try:
                output, meta = await self.gateway.structured(
                    role=self.model_role,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    output_model=PlanOutput,
                    prompt_version=self.prompt_version,
                )
                state.budget.model_calls_used += 1
                default = output
                model_id = meta.model_id
            except Exception as exc:
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

    def _create_default_plan(self, state: AgentState) -> PlanOutput | None:
        if state.scenario == Scenario.CODE_AUDIT:
            return PlanOutput(
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

        if state.scenario == Scenario.PENETRATION_TEST:
            return PlanOutput(
                steps=[
                    PlanStep(
                        step_id="pentest-recon",
                        objective="Discover open ports and services on the target.",
                        agent_role="executor",
                        tool_candidates=["nmap_scan", "whatweb_identify"],
                        inputs={"target": "."},
                        success_criteria=[
                            "Nmap scan produces a structured result",
                            "At least one open port or service is identified",
                        ],
                        risk_hint=RiskLevel.R2,
                        max_attempts=2,
                    ),
                    PlanStep(
                        step_id="pentest-enumerate",
                        objective="Enumerate web directories and known vulnerabilities.",
                        agent_role="executor",
                        tool_candidates=["gobuster_dir", "nuclei_scan"],
                        inputs={},
                        success_criteria=[
                            "Directory enumeration completes successfully",
                            "Nuclei scan identifies potential vulnerabilities",
                        ],
                        risk_hint=RiskLevel.R2,
                        max_attempts=2,
                    ),
                ],
                rationale_summary="Reconnaissance first, then targeted enumeration based on findings.",
            )

        if state.scenario == Scenario.LOG_ANALYSIS:
            return PlanOutput(
                steps=[
                    PlanStep(
                        step_id="log-inspect",
                        objective="Analyze log files for suspicious patterns and anomalies.",
                        agent_role="executor",
                        tool_candidates=["log_inspector"],
                        inputs={"target": "."},
                        success_criteria=[
                            "Log entries are parsed and categorized",
                            "Anomalous patterns are identified",
                        ],
                        risk_hint=RiskLevel.R1,
                        max_attempts=2,
                    ),
                ],
                rationale_summary="Inspect logs for indicators of compromise and anomalous activity.",
            )

        return None


class AnalystAgent(BaseAgent):
    name = "analyst"
    model_role = "planner"

    @staticmethod
    def _build_attack_keywords(state: AgentState) -> list[tuple[str, KnowledgeHit]]:
        """Build a list of (keyword, hit) pairs from knowledge hits for fuzzy matching."""
        pairs: list[tuple[str, KnowledgeHit]] = []
        seen = set()
        for hit in state.knowledge_hits:
            attack_id = hit.metadata.get("attack_id", "")
            technique_name = hit.metadata.get("technique_name", "")
            content_lower = hit.content.lower()
            # 用 ATT&CK ID、技术名、关键词做匹配依据
            tokens = [t for t in [attack_id, technique_name] if t]
            for token in tokens:
                key = token.lower()
                if key and key not in seen:
                    pairs.append((key, hit))
                    seen.add(key)
            # 从 content 提取简短关键词做辅助匹配
            for keyword in ("sql", "xss", "injection", "bypass", "privilege", "escalation", "discovery"):
                if keyword in content_lower and keyword not in seen:
                    pairs.append((keyword, hit))
                    seen.add(keyword)
        return pairs

    @staticmethod
    def _match_finding_to_attack(
        finding: Finding,
        keyword_pairs: list[tuple[str, KnowledgeHit]],
    ) -> list[str]:
        """Return ATT&CK IDs that match a finding based on title/description keywords."""
        haystack = f"{finding.title} {finding.description}".lower()
        matched: list[str] = []
        seen_id = set()
        for keyword, hit in keyword_pairs:
            attack_id = hit.metadata.get("attack_id", "")
            if keyword in haystack and attack_id and attack_id not in seen_id:
                matched.append(attack_id)
                seen_id.add(attack_id)
        return matched

    async def run(self, state: AgentState) -> AgentState:
        if not state.observations:
            return state
        latest = state.observations[-1]
        if latest.status == ToolStatus.SUCCESS:
            state.evidence.extend(latest.evidence)
            for item in latest.data.get("findings", []):
                finding = Finding.model_validate(item)
                # 交叉关联 ATT&CK 知识
                if state.knowledge_hits:
                    keywords = self._build_attack_keywords(state)
                    matched_ids = self._match_finding_to_attack(finding, keywords)
                    if matched_ids:
                        raw = {"attck_ids": matched_ids}
                        finding.raw.update(raw)
                state.findings.append(finding)

            ref_count = sum(
                1 for f in state.findings[-len(latest.data.get("findings", [])):]
                if "attck_ids" in f.raw
            )
            rationale = latest.summary
            if ref_count:
                rationale += f" | {ref_count} finding(s) cross-referenced to ATT&CK"

            state.decisions.append(
                DecisionRecord(
                    decision="tool_result_normalized",
                    rationale_summary=rationale,
                    evidence_ids=[item.evidence_id for item in latest.evidence],
                    policy_ids=["EVIDENCE-REQUIRED-V1", "RAG-CITATION-V1"],
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

    @staticmethod
    def _build_knowledge_summary(state: AgentState) -> str:
        """Build a human-readable block listing ATT&CK knowledge sources referenced in the run."""
        if not state.knowledge_hits:
            return ""
        lines: list[str] = []
        seen_id = set()
        for hit in state.knowledge_hits:
            attack_id = hit.metadata.get("attack_id", "")
            if attack_id and attack_id not in seen_id:
                name = hit.metadata.get("technique_name", "")
                lines.append(f"  - {attack_id} {name}".strip())
                seen_id.add(attack_id)
        # 也从 finding 的 attck_ids 收集
        for finding in state.findings:
            for aid in finding.raw.get("attck_ids", []):
                if aid not in seen_id:
                    lines.append(f"  - {aid}")
                    seen_id.add(aid)
        if not lines:
            return ""
        return "ATT&CK knowledge referenced:\n" + "\n".join(lines)

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

        # 构建带有 ATT&CK 引用的报告摘要
        knowledge_summary = self._build_knowledge_summary(state)
        if successful:
            attck_ref_count = sum(1 for f in state.findings if "attck_ids" in f.raw)
            summary = (
                f"Code audit completed with {len(state.findings)} finding(s), "
                f"supported by {len(state.evidence)} evidence record(s)."
            )
            if attck_ref_count:
                summary += f" {attck_ref_count} finding(s) cross-referenced to ATT&CK."
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

        # 将 ATT&CK 知识引用写入 DecisionRecord 供展示
        if knowledge_summary:
            state.decisions.append(
                DecisionRecord(
                    decision="knowledge_citation",
                    rationale_summary=knowledge_summary,
                    policy_ids=["RAG-CITATION-V1"],
                    model_id="deterministic-citation",
                )
            )

        return state
