from __future__ import annotations

from pathlib import Path

import pytest

from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry, default_registry


class ControlledAuditTool(BaseTool):
    def __init__(self, risk: RiskLevel, fail_once: bool = False) -> None:
        self.manifest = ToolManifest(
            name="bandit_python_audit",
            version="test",
            description="controlled test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=risk,
        )
        self.fail_once = fail_once
        self.calls = 0

    async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
        self.calls += 1
        if self.fail_once and self.calls == 1:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="TRANSIENT",
                error_message="temporary failure",
            )
        return ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="ok")


def controlled_orchestrator(settings, risk: RiskLevel, fail_once: bool = False):
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')", encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    tool = ControlledAuditTool(risk, fail_once)
    registry.register(tool)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(registry, Guardrail()),
    )
    return orchestrator, ledger, tool


@pytest.mark.asyncio
async def test_code_audit_end_to_end(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    (settings.input_root / "bad.py").write_text(
        "import subprocess\nsubprocess.Popen('echo unsafe', shell=True)\n", encoding="utf-8"
    )
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
    )
    state = await orchestrator.start(
        TaskRequest(
            objective="审计 Python 代码并给出漏洞报告",
            attachments=[AttachmentRef(ref="bad.py")],
        ),
        "e2e-run",
    )
    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    assert state.report.findings
    assert state.report.evidence
    assert ledger.verify("e2e-run")
    event_types = [event.event_type for event in ledger.events("e2e-run")]
    assert "guardrail.evaluated" in event_types
    assert "report.generated" in event_types


@pytest.mark.asyncio
async def test_r2_tool_interrupts_and_resumes(settings) -> None:
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(
        TaskRequest(
            objective="audit code",
            attachments=[AttachmentRef(ref="app.py")],
            autonomy_policy="graded",
        ),
        "approval-run",
    )
    assert waiting.status == RunStatus.WAITING_APPROVAL
    assert waiting.pending_approval is not None
    completed = await orchestrator.resume(
        "approval-run", ApprovalResponse(decision=ApprovalDecision.APPROVE, reason="authorized")
    )
    assert completed.status == RunStatus.COMPLETED
    assert tool.calls == 1
    assert ledger.verify("approval-run")


@pytest.mark.asyncio
async def test_r3_tool_is_denied_without_execution(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R3)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "denied-run",
    )
    assert state.status == RunStatus.DENIED
    assert tool.calls == 0


@pytest.mark.asyncio
async def test_idempotent_tool_failure_is_retried(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R1, fail_once=True)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "retry-run",
    )
    assert state.status == RunStatus.COMPLETED
    assert state.retry_counts["audit-python-bandit"] == 1
    assert tool.calls == 2


@pytest.mark.asyncio
async def test_unsupported_scenario_produces_partial_report(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = await orchestrator.start(TaskRequest(objective="分析网络流量异常"), "log-run")
    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    assert state.report.limitations
