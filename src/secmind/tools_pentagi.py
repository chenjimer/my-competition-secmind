"""Pentagi-inspired security tool wrappers for SecMind.

Provides BaseTool implementations for common penetration testing tools
(nmap, sqlmap, nuclei, gobuster, whatweb, hydra, nikto, searchsploit)
that are executed inside Docker sandbox containers for isolation.
"""

from __future__ import annotations

import json
import time
from typing import Any

from secmind.sandbox import SandboxConfig, SandboxExecutor, SandboxError
from secmind.schemas import (
    Evidence,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.tools import BaseTool


class NmapTool(BaseTool):
    """Network port scanner using nmap inside a Docker sandbox."""

    manifest = ToolManifest(
        name="nmap_scan",
        version="1",
        description="Run nmap port scan against a target host. Returns open ports, services, and versions.",
        scenarios=[Scenario.PENETRATION_TEST, Scenario.LOG_ANALYSIS],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Port range (e.g., 1-1000 or 80,443,8080)", "default": "1-1000"},
                "scan_type": {"type": "string", "enum": ["tcp", "syn"], "description": "Scan technique", "default": "tcp"},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "ports": {"type": "array", "items": {"type": "object"}},
                "raw_output": {"type": "string"},
            },
        },
        risk_level=RiskLevel.R2,
        permissions=["network:outbound"],
        timeout_seconds=600,
        idempotent=True,
        requires_network=True,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        target = args.get("target", "")
        ports = args.get("ports", "1-1000")
        scan_type = args.get("scan_type", "tcp")

        if not target:
            return ToolResult(status=ToolStatus.ERROR, error_code="INVALID_ARGS", error_message="target is required")

        scan_flag = "-sT" if scan_type == "tcp" else "-sS"
        cmd = ["nmap", scan_flag, "-p", ports, "-oG", "-", target]

        sandbox = SandboxExecutor(SandboxConfig(
            network_enabled=True,
            timeout_seconds=self.manifest.timeout_seconds,
        ))

        # Check image availability
        try:
            await sandbox.ensure_image()
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_NOT_READY", error_message=str(exc))

        try:
            result = await sandbox.execute(cmd)
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_FAILED", error_message=str(exc))

        parsed = SandboxExecutor.parse_nmap_output(result.stdout)
        evidence_id = str(hash(result.stdout))[:24]
        evidence = [
            Evidence(
                evidence_id=evidence_id,
                source=f"nmap:{self.manifest.version}",
                summary=f"nmap scan of {target}:{ports} - {len(parsed)} open ports",
                metadata={"target": target, "ports": ports, "open_count": len(parsed)},
            )
        ]

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"ports": parsed, "raw_output": result.stdout[:5000]},
            summary=f"nmap scan completed: {len(parsed)} open port(s) on {target}",
            evidence=evidence,
            duration_ms=result.duration_ms,
        )


class NucleiTool(BaseTool):
    """Vulnerability scanner using nuclei inside a Docker sandbox."""

    manifest = ToolManifest(
        name="nuclei_scan",
        version="1",
        description="Run nuclei vulnerability template scanner against a target URL or host.",
        scenarios=[Scenario.PENETRATION_TEST],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g., http://example.com)"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Minimum severity", "default": "medium"},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}},
            },
        },
        risk_level=RiskLevel.R2,
        permissions=["network:outbound"],
        timeout_seconds=600,
        idempotent=True,
        requires_network=True,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        target = args.get("target", "")
        severity = args.get("severity", "medium")

        if not target:
            return ToolResult(status=ToolStatus.ERROR, error_code="INVALID_ARGS", error_message="target is required")

        cmd = ["nuclei", "-u", target, "-severity", severity, "-json", "-silent"]

        sandbox = SandboxExecutor(SandboxConfig(
            network_enabled=True,
            timeout_seconds=self.manifest.timeout_seconds,
        ))

        try:
            await sandbox.ensure_image()
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_NOT_READY", error_message=str(exc))

        try:
            result = await sandbox.execute(cmd)
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_FAILED", error_message=str(exc))

        findings = SandboxExecutor.parse_nuclei_json(result.stdout)
        evidence_id = str(hash(result.stdout))[:24]
        evidence = [
            Evidence(
                evidence_id=evidence_id,
                source=f"nuclei:{self.manifest.version}",
                summary=f"nuclei scan of {target} - {len(findings)} vulnerabilities found",
                metadata={"target": target, "severity": severity, "finding_count": len(findings)},
            )
        ]

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"findings": findings},
            summary=f"nuclei scan completed: {len(findings)} finding(s) on {target}",
            evidence=evidence,
            duration_ms=result.duration_ms,
        )


class GobusterTool(BaseTool):
    """Directory/file enumeration using gobuster inside a Docker sandbox."""

    manifest = ToolManifest(
        name="gobuster_dir",
        version="1",
        description="Enumerate directories and files on a web server using gobuster.",
        scenarios=[Scenario.PENETRATION_TEST],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g., http://example.com)"},
                "wordlist": {"type": "string", "description": "Wordlist path inside container", "default": "/usr/share/wordlists/dirb/common.txt"},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "directories": {"type": "array", "items": {"type": "object"}},
            },
        },
        risk_level=RiskLevel.R2,
        permissions=["network:outbound"],
        timeout_seconds=300,
        idempotent=True,
        requires_network=True,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        target = args.get("target", "")
        if not target:
            return ToolResult(status=ToolStatus.ERROR, error_code="INVALID_ARGS", error_message="target is required")

        cmd = ["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-o", "/dev/stdout"]

        sandbox = SandboxExecutor(SandboxConfig(
            network_enabled=True,
            timeout_seconds=self.manifest.timeout_seconds,
        ))

        try:
            await sandbox.ensure_image()
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_NOT_READY", error_message=str(exc))

        try:
            result = await sandbox.execute(cmd)
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_FAILED", error_message=str(exc))

        directories = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].startswith("/"):
                directories.append({"path": parts[0], "status": parts[1]})

        evidence_id = str(hash(result.stdout))[:24]
        evidence = [Evidence(
            evidence_id=evidence_id,
            source=f"gobuster:{self.manifest.version}",
            summary=f"Directory enumeration on {target} - {len(directories)} found",
            metadata={"target": target, "found": len(directories)},
        )]

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"directories": directories},
            summary=f"gobuster completed: {len(directories)} path(s) discovered",
            evidence=evidence,
            duration_ms=result.duration_ms,
        )


class WhatwebTool(BaseTool):
    """Web technology identification using whatweb."""

    manifest = ToolManifest(
        name="whatweb_identify",
        version="1",
        description="Identify web technologies, frameworks, and CMS on a target website.",
        scenarios=[Scenario.PENETRATION_TEST, Scenario.LOG_ANALYSIS],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "technologies": {"type": "array", "items": {"type": "object"}},
            },
        },
        risk_level=RiskLevel.R1,
        permissions=["network:outbound"],
        timeout_seconds=120,
        idempotent=True,
        requires_network=True,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        target = args.get("target", "")
        if not target:
            return ToolResult(status=ToolStatus.ERROR, error_code="INVALID_ARGS", error_message="target is required")

        cmd = ["whatweb", target, "--log-json=/dev/stdout", "--quiet"]
        sandbox = SandboxExecutor(SandboxConfig(
            network_enabled=True,
            timeout_seconds=self.manifest.timeout_seconds,
        ))

        try:
            await sandbox.ensure_image()
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_NOT_READY", error_message=str(exc))

        try:
            result = await sandbox.execute(cmd)
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_FAILED", error_message=str(exc))

        evidence_id = str(hash(result.stdout))[:24]
        evidence = [Evidence(
            evidence_id=evidence_id,
            source=f"whatweb:{self.manifest.version}",
            summary=f"Web technology identification for {target}",
            metadata={"target": target},
        )]

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"technologies": result.stdout[:5000]},
            summary=f"whatweb identified technologies on {target}",
            evidence=evidence,
            duration_ms=result.duration_ms,
        )


class SearchsploitTool(BaseTool):
    """Exploit search using searchsploit."""

    manifest = ToolManifest(
        name="searchsploit_query",
        version="1",
        description="Search Exploit-DB for known exploits matching a keyword, CVE, or software name.",
        scenarios=[Scenario.PENETRATION_TEST],
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term (e.g., CVE number, software name)"},
            },
            "required": ["query"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "results": {"type": "array", "items": {"type": "object"}},
            },
        },
        risk_level=RiskLevel.R1,
        permissions=[],
        timeout_seconds=60,
        idempotent=True,
        requires_network=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        query = args.get("query", "")
        if not query:
            return ToolResult(status=ToolStatus.ERROR, error_code="INVALID_ARGS", error_message="query is required")

        cmd = ["searchsploit", query, "--json"]
        sandbox = SandboxExecutor(SandboxConfig(
            network_enabled=True,
            timeout_seconds=self.manifest.timeout_seconds,
        ))

        try:
            await sandbox.ensure_image()
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_NOT_READY", error_message=str(exc))

        try:
            result = await sandbox.execute(cmd)
        except SandboxError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="SANDBOX_FAILED", error_message=str(exc))

        parsed = {}
        try:
            parsed = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            pass

        exploits = parsed.get("RESULTS_EXPLOIT", []) if isinstance(parsed, dict) else []
        evidence_id = str(hash(result.stdout))[:24]
        evidence = [Evidence(
            evidence_id=evidence_id,
            source=f"searchsploit:{self.manifest.version}",
            summary=f"Exploit search for '{query}' - {len(exploits)} results",
            metadata={"query": query, "count": len(exploits)},
        )]

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"results": exploits},
            summary=f"searchsploit found {len(exploits)} exploit(s) for '{query}'",
            evidence=evidence,
            duration_ms=result.duration_ms,
        )


def pentagi_tools() -> list[BaseTool]:
    """Return all pentagi-inspired tool instances for registration."""
    return [
        NmapTool(),
        NucleiTool(),
        GobusterTool(),
        WhatwebTool(),
        SearchsploitTool(),
    ]
