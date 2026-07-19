from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from secmind.sandbox import SandboxResult
from secmind.schemas import ToolContext, ToolStatus
from secmind.tools_pentagi import (
    GobusterTool,
    NmapTool,
    NucleiTool,
    SearchsploitTool,
    WhatwebTool,
    pentagi_tools,
)


@pytest.fixture
def tool_context(tmp_path) -> ToolContext:
    return ToolContext(
        run_id="test-run",
        step_id="test-step",
        workspace=str(tmp_path),
        allowed_paths=[str(tmp_path)],
    )


class TestPentagiToolsRegistration:
    """Verify all pentest tools register correctly."""

    def test_pentagi_tools_returns_all(self) -> None:
        tools = pentagi_tools()
        names = {t.manifest.name for t in tools}
        assert names == {"nmap_scan", "nuclei_scan", "gobuster_dir", "whatweb_identify", "searchsploit_query"}
        assert len(tools) == 5

    def test_each_tool_has_valid_manifest(self) -> None:
        for tool in pentagi_tools():
            m = tool.manifest
            assert m.name
            assert m.version
            assert m.description
            assert m.input_schema
            assert m.timeout_seconds > 0


class TestNmapTool:
    @pytest.mark.asyncio
    async def test_rejects_empty_target(self, tool_context: ToolContext) -> None:
        result = await NmapTool().invoke({"target": ""}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "INVALID_ARGS"

    @pytest.mark.asyncio
    async def test_successful_scan(self, tool_context: ToolContext) -> None:
        mock_result = SandboxResult(
            stdout="22 open tcp ssh\n80 open tcp http\n443 open tcp https",
            stderr="",
            exit_code=0,
            duration_ms=1500,
        )
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await NmapTool().invoke({"target": "scanme.nmap.org", "ports": "22,80,443"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert len(result.data["ports"]) == 3
        assert result.data["ports"][0]["port"] == 22
        assert result.data["ports"][1]["port"] == 80
        assert result.data["ports"][2]["port"] == 443
        assert result.evidence
        assert result.duration_ms == 1500

    @pytest.mark.asyncio
    async def test_sandbox_not_ready(self, tool_context: ToolContext) -> None:
        from secmind.sandbox import SandboxError

        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(side_effect=SandboxError("Image not found"))),
        ):
            result = await NmapTool().invoke({"target": "scanme.nmap.org"}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "SANDBOX_NOT_READY"


class TestNucleiTool:
    @pytest.mark.asyncio
    async def test_rejects_empty_target(self, tool_context: ToolContext) -> None:
        result = await NucleiTool().invoke({"target": ""}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "INVALID_ARGS"

    @pytest.mark.asyncio
    async def test_successful_scan(self, tool_context: ToolContext) -> None:
        mock_stdout = (
            '{"template-id": "ssl-diff-hellman", "info": {"name": "SSL Diffie-Hellman", "severity": "medium"}, "matched-at": "https://example.com", "extracted-results": []}\n'
            '{"template-id": "missing-hsts", "info": {"name": "Missing HSTS Header", "severity": "low"}, "matched-at": "https://example.com", "extracted-results": []}'
        )
        mock_result = SandboxResult(stdout=mock_stdout, stderr="", exit_code=0, duration_ms=3000)
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await NucleiTool().invoke({"target": "https://example.com", "severity": "low"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert len(result.data["findings"]) == 2
        assert result.data["findings"][0]["template"] == "ssl-diff-hellman"
        assert result.data["findings"][1]["template"] == "missing-hsts"


class TestGobusterTool:
    @pytest.mark.asyncio
    async def test_rejects_empty_target(self, tool_context: ToolContext) -> None:
        result = await GobusterTool().invoke({"target": ""}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "INVALID_ARGS"

    @pytest.mark.asyncio
    async def test_successful_enumeration(self, tool_context: ToolContext) -> None:
        mock_result = SandboxResult(
            stdout="/admin (Status: 200)\n/login (Status: 200)\n/backup (Status: 301)",
            stderr="",
            exit_code=0,
            duration_ms=5000,
        )
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await GobusterTool().invoke({"target": "http://example.com"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert len(result.data["directories"]) == 3
        assert result.data["directories"][0]["path"] == "/admin"
        assert result.data["directories"][1]["path"] == "/login"


class TestWhatwebTool:
    @pytest.mark.asyncio
    async def test_rejects_empty_target(self, tool_context: ToolContext) -> None:
        result = await WhatwebTool().invoke({"target": ""}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "INVALID_ARGS"

    @pytest.mark.asyncio
    async def test_successful_identification(self, tool_context: ToolContext) -> None:
        mock_result = SandboxResult(
            stdout='{"http://example.com": {"title": ["Example Domain"], "server": ["ECS"], "Content-Type": ["text/html"}}',
            stderr="",
            exit_code=0,
            duration_ms=2000,
        )
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await WhatwebTool().invoke({"target": "http://example.com"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert "example.com" in result.data["technologies"]
        assert result.evidence


class TestSearchsploitTool:
    @pytest.mark.asyncio
    async def test_rejects_empty_query(self, tool_context: ToolContext) -> None:
        result = await SearchsploitTool().invoke({"query": ""}, tool_context)
        assert result.status == ToolStatus.ERROR
        assert result.error_code == "INVALID_ARGS"

    @pytest.mark.asyncio
    async def test_successful_search(self, tool_context: ToolContext) -> None:
        mock_result = SandboxResult(
            stdout='{"RESULTS_EXPLOIT": [{"Title": "WordPress 5.0 XSS", "EDB-ID": "47103"}, {"Title": "Apache 2.4.49 RCE", "EDB-ID": "47104"}]}',
            stderr="",
            exit_code=0,
            duration_ms=1000,
        )
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await SearchsploitTool().invoke({"query": "apache"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert len(result.data["results"]) == 2
        assert result.data["results"][0]["EDB-ID"] == "47103"

    @pytest.mark.asyncio
    async def test_empty_search_results(self, tool_context: ToolContext) -> None:
        mock_result = SandboxResult(stdout="{}", stderr="", exit_code=0, duration_ms=500)
        with (
            patch("secmind.tools_pentagi.SandboxExecutor.ensure_image", AsyncMock(return_value=True)),
            patch("secmind.tools_pentagi.SandboxExecutor.execute", AsyncMock(return_value=mock_result)),
        ):
            result = await SearchsploitTool().invoke({"query": "nonexistent_software_xyz"}, tool_context)
        assert result.status == ToolStatus.SUCCESS
        assert result.data["results"] == []
