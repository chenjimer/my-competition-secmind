from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from secmind.guardrail import Guardrail, GuardrailDecision
from secmind.schemas import (
    Evidence,
    Finding,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)


class ToolError(RuntimeError):
    pass


class BaseTool(ABC):
    manifest: ToolManifest

    @abstractmethod
    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        raise NotImplementedError


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.manifest.name in self._tools:
            raise ToolError(f"Duplicate tool: {tool.manifest.name}")
        self._tools[tool.manifest.name] = tool

    def get(self, name: str) -> BaseTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolError(f"Unknown tool: {name}") from exc

    def manifests(self) -> list[ToolManifest]:
        return [tool.manifest for tool in self._tools.values()]


class ToolBroker:
    def __init__(self, registry: ToolRegistry, guardrail: Guardrail) -> None:
        self.registry = registry
        self.guardrail = guardrail

    def assess(self, name: str, args: dict[str, Any], autonomy_policy: str) -> GuardrailDecision:
        return self.guardrail.evaluate(self.registry.get(name).manifest, args, autonomy_policy)

    async def invoke(self, name: str, args: dict[str, Any], context: ToolContext) -> ToolResult:
        return await self.registry.get(name).invoke(args, context)


REMEDIATIONS = {
    "B105": "Move hard-coded secrets to an injected secret store and rotate exposed values.",
    "B301": "Avoid unsafe deserialization; use a safe, schema-validated format such as JSON.",
    "B602": "Avoid shell=True and pass a fixed argument vector to subprocess APIs.",
    "B608": "Use parameterized queries rather than constructing SQL with string interpolation.",
}


class BanditTool(BaseTool):
    manifest = ToolManifest(
        name="bandit_python_audit",
        version="1",
        description="Run Bandit static security analysis over Python source in the controlled workspace.",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=120,
        idempotent=True,
        requires_network=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = self._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(
                status=ToolStatus.DENIED,
                error_code="TOOL_SCOPE_VIOLATION",
                error_message=str(exc),
            )
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(target),
            "-f",
            "json",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=context.workspace,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.manifest.timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.communicate()
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="TOOL_TIMEOUT",
                error_message="Bandit exceeded its execution deadline.",
            )
        if process.returncode not in {0, 1}:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_FAILED",
                error_message=stderr.decode(errors="replace")[-2000:],
            )
        try:
            body = json.loads(stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError as exc:
            return ToolResult(
                status=ToolStatus.ERROR,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="BANDIT_INVALID_JSON",
                error_message=str(exc),
            )
        evidence: list[Evidence] = []
        findings: list[dict[str, Any]] = []
        for item in body.get("results", []):
            evidence_id = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
            ev = Evidence(
                evidence_id=evidence_id,
                source=f"bandit:{self.manifest.version}",
                summary=f"{item.get('test_id', 'UNKNOWN')} at {item.get('filename')}:{item.get('line_number')}",
                metadata={
                    "tool_version": self.manifest.version,
                    "test_id": item.get("test_id"),
                    "test_name": item.get("test_name"),
                },
            )
            evidence.append(ev)
            finding = Finding(
                rule_id=item.get("test_id", "UNKNOWN"),
                severity=item.get("issue_severity", "UNKNOWN"),
                confidence=item.get("issue_confidence", "UNKNOWN"),
                path=item.get("filename", "unknown"),
                line=item.get("line_number"),
                title=item.get("test_name", item.get("test_id", "Bandit finding")),
                description=item.get("issue_text", ""),
                remediation=REMEDIATIONS.get(item.get("test_id")),
                evidence_ids=[evidence_id],
                raw=item,
            )
            findings.append(finding.model_dump(mode="json"))
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"findings": findings, "metrics": body.get("metrics", {})},
            summary=f"Bandit completed with {len(findings)} finding(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _resolve_target(value: str, context: ToolContext) -> Path:
        workspace = Path(context.workspace).resolve()
        candidate = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        allowed = [Path(path).resolve() for path in context.allowed_paths]
        if not any(candidate == root or root in candidate.parents for root in allowed):
            raise ToolError("Tool target is outside the allowed workspace")
        if not candidate.exists():
            raise ToolError("Tool target does not exist")
        return candidate


# ──────────────────────────────────────────────
# Log Analysis — simple regex-based log inspector
# ──────────────────────────────────────────────

# Suspicious patterns for log analysis (value = severity label)
_SUSPICIOUS_PATTERNS: dict[str, str] = {
    # SQL injection indicators
    r"(?i)\bSELECT\b.*\bFROM\b": "HIGH",
    r"(?i)\bUNION\b.*\bSELECT\b": "CRITICAL",
    r"(?i)(\%27|\'|--|;)\s*(or|and)\s+": "HIGH",
    # Path traversal
    r"\.\./\.\./": "HIGH",
    r"\.\.\\\.\.\\": "HIGH",
    # XSS indicators
    r"(?i)<script[^>]*>": "HIGH",
    r"(?i)alert\s*\(": "MEDIUM",
    r"(?i)onerror\s*=": "MEDIUM",
    # Command injection
    r"(?i)(\||;|`)\s*(cat|wget|curl|bash|sh|powershell)\s": "CRITICAL",
    # Brute-force / scanning
    r"(?i)(admin|root|sa)\s*(login|auth|failed)": "MEDIUM",
    # Shellshock
    r"\(\)\s*\{": "CRITICAL",
    # RFI / LFI
    r"(?i)(file|php|data)://": "HIGH",
}

_COMMON_LOG_PATTERNS: list[tuple[str, str, list[str]]] = [
    # Apache / Nginx combined log format
    (
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+|-)',
        "web_access",
        ["remote_addr", "timestamp", "method", "path", "protocol", "status", "size"],
    ),
    # Auth log (sshd, sudo failures)
    (
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)",
        "syslog",
        ["timestamp", "host", "service", "pid", "message"],
    ),
    # JSON-line log (common in modern apps)
    (
        r'^\{"timestamp":\s*"',
        "json_log",
        [],
    ),
]


class LogAnalysisTool(BaseTool):
    """Analyze log files for suspicious patterns, anomalies, and IOCs.

    Supports common log formats (Apache/Nginx access logs, syslog/auth logs,
    JSON-line logs) and detects brute-force attempts, SQL injection, XSS,
    path traversal, and other security-relevant patterns.
    """

    manifest = ToolManifest(
        name="log_inspector",
        version="1",
        description="Analyze log files for suspicious patterns, anomalies, and indicators of compromise.",
        scenarios=[Scenario.LOG_ANALYSIS],
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "File or directory path to analyze"},
                "min_severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "Minimum severity to report",
                    "default": "LOW",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Maximum lines to scan per file",
                    "default": 50000,
                },
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
            },
        },
        risk_level=RiskLevel.R1,
        permissions=["workspace:read"],
        timeout_seconds=120,
        idempotent=True,
        requires_network=False,
    )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        started = time.monotonic()
        try:
            target = self._resolve_target(str(args.get("target", ".")), context)
        except ToolError as exc:
            return ToolResult(
                status=ToolStatus.DENIED,
                error_code="TOOL_SCOPE_VIOLATION",
                error_message=str(exc),
            )

        min_severity = str(args.get("min_severity", "LOW"))
        max_lines = int(args.get("max_lines", 50000))
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_sev_idx = severity_order.index(min_severity) if min_severity in severity_order else 0

        findings: list[dict[str, Any]] = []
        evidence: list[Evidence] = []
        files_scanned = 0
        total_lines = 0
        severity_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        unique_ips: set[str] = set()
        failed_auth_attempts: list[dict[str, Any]] = []

        log_files = [target] if target.is_file() else sorted(target.rglob("*")) if target.is_dir() else []
        log_files = [f for f in log_files if f.is_file() and self._is_log_file(f)]

        for log_file in log_files[:20]:  # limit to 20 files
            if files_scanned >= 20:
                break
            files_scanned += 1
            relative = str(log_file.relative_to(context.workspace)) if context.workspace else log_file.name

            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = text.splitlines()
            total_lines += len(lines)
            detected_format = self._detect_format(lines)

            for line_num, line in enumerate(lines[:max_lines], 1):
                # Check suspicious patterns
                for pattern_raw, sev in _SUSPICIOUS_PATTERNS.items():
                    sev_idx = severity_order.index(sev) if sev in severity_order else 0
                    if sev_idx < min_sev_idx:
                        continue
                    if re.search(pattern_raw, line):
                        key = sev
                        severity_counts[key] = severity_counts.get(key, 0) + 1
                        # Extract IP if present
                        ip_match = re.match(r"^(\S+)", line)
                        ip = ip_match.group(1) if ip_match else "unknown"
                        if ip and ip != "unknown":
                            unique_ips.add(ip)
                        finding = Finding(
                            rule_id=f"LOG-{sev}-{len(findings)+1:04d}",
                            severity=sev,  # type: ignore[arg-type]
                            confidence="HIGH",
                            path=relative,
                            line=line_num,
                            title=f"Suspicious pattern detected ({sev})",
                            description=f"Line {line_num}: {line[:200]}",
                            remediation="Investigate the source IP and verify whether this is legitimate traffic.",
                            raw={"pattern": pattern_raw, "severity": sev, "line": line[:500], "ip": ip},
                        )
                        findings.append(finding.model_dump(mode="json"))
                        break  # one finding per line

                # Auth failure tracking (independent of suspicious patterns)
                if re.search(r"(?i)(failed|invalid)\s+(password|login|auth)", line):
                    ip_auth = re.match(r"^(\S+)", line)
                    ip_val = ip_auth.group(1) if ip_auth else "unknown"
                    failed_auth_attempts.append({"ip": ip_val, "line": line_num, "file": relative})

            # Add file-level evidence
            if detected_format:
                ev = Evidence(
                    evidence_id=hashlib.sha256(f"{relative}:{detected_format}".encode()).hexdigest()[:24],
                    source=f"log_inspector:{self.manifest.version}",
                    summary=f"Scanned {relative} ({len(lines)} lines, format: {detected_format})",
                    metadata={"file": relative, "format": detected_format, "lines": len(lines)},
                )
                evidence.append(ev)

        # Detect brute force from failed auth attempts
        ip_counts: dict[str, int] = {}
        for attempt in failed_auth_attempts:
            ip_counts[attempt["ip"]] = ip_counts.get(attempt["ip"], 0) + 1

        for ip_addr, count in ip_counts.items():
            if count >= 5 and min_sev_idx <= severity_order.index("MEDIUM"):
                severity_counts["MEDIUM"] = severity_counts.get("MEDIUM", 0) + 1
                findings.append(
                    Finding(
                        rule_id="LOG-BRUTE-MEDIUM",
                        severity="MEDIUM",
                        confidence="HIGH",
                        path="(multiple files)",
                        title=f"Brute-force attempt detected from {ip_addr}",
                        description=f"{count} failed auth attempts from {ip_addr}",
                        remediation="Block the source IP and review authentication logs.",
                        raw={"ip": ip_addr, "failed_attempts": count, "type": "brute_force"},
                    ).model_dump(mode="json")
                )
                if ip_addr not in unique_ips:
                    unique_ips.add(ip_addr)

        # Build summary
        summary_data = {
            "files_scanned": files_scanned,
            "total_lines": total_lines,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "unique_ips": sorted(unique_ips),
        }

        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"findings": findings, "summary": summary_data},
            summary=f"Log analysis completed: {len(findings)} finding(s) across {files_scanned} file(s).",
            evidence=evidence,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _detect_format(lines: list[str]) -> str:
        if not lines:
            return "unknown"
        for prefix, fmt_name, _ in _COMMON_LOG_PATTERNS:
            if re.match(prefix, lines[0]):
                return fmt_name
        return "plain"

    @staticmethod
    def _is_log_file(path: Path) -> bool:
        suffixes = {".log", ".txt", ".out", ".err"}
        names = {"access.log", "error.log", "auth.log", "syslog", "messages", "secure"}
        return path.suffix.lower() in suffixes or path.name.lower() in names or (
            path.stat().st_size < 50 * 1024 * 1024 and _is_text_file(path)
        )

    @staticmethod
    def _resolve_target(value: str, context: ToolContext) -> Path:
        workspace = Path(context.workspace).resolve()
        candidate = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        allowed = [Path(path).resolve() for path in context.allowed_paths]
        if not any(candidate == root or root in candidate.parents for root in allowed):
            raise ToolError("Tool target is outside the allowed workspace")
        if not candidate.exists():
            raise ToolError("Tool target does not exist")
        return candidate


def _is_text_file(path: Path) -> bool:
    """Quick heuristic: check if a file looks like text by inspecting first bytes."""
    try:
        chunk = path.read_bytes()[:512]
        return not any(b == 0 for b in chunk)
    except Exception:
        return False


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(BanditTool())
    registry.register(LogAnalysisTool())
    try:
        from secmind.tools_pentagi import pentagi_tools
        for tool in pentagi_tools():
            registry.register(tool)
    except Exception as exc:
        import sys
        sys.stderr.write(f"Warning: Failed to load pentagi tools: {exc}\n")
    try:
        from secmind.skills_loader import SkillsLoader
        import os
        skills_dir = os.environ.get("SECMIND_SKILLS_DIR", "")
        if skills_dir:
            loader = SkillsLoader(skills_dir)
            count = loader.register_all(registry)
            if count > 0:
                import sys
                sys.stderr.write(f"Loaded {count} skill(s) from {skills_dir}\n")
    except Exception as exc:
        import sys
        sys.stderr.write(f"Warning: Failed to load skills: {exc}\n")
    return registry
