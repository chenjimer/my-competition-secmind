from __future__ import annotations

from pathlib import Path

import pytest

from secmind.schemas import ToolContext, ToolStatus
from secmind.tools import BanditTool


@pytest.mark.asyncio
async def test_bandit_tool_produces_evidence(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("import subprocess\nsubprocess.Popen('echo unsafe', shell=True)\n", encoding="utf-8")
    result = await BanditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"]
    assert result.evidence
    assert result.data["findings"][0]["evidence_ids"]


@pytest.mark.asyncio
async def test_bandit_tool_rejects_scope_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent
    result = await BanditTool().invoke(
        {"target": str(outside)},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )
    assert result.status == ToolStatus.DENIED
