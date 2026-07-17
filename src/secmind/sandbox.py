"""Docker sandbox executor for isolated security tool execution.

Provides a managed Docker container environment for running security tools
in isolation, with resource limits, timeouts, and network controls.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SANDBOX_IMAGE = "secmind-sandbox:latest"
_SANDBOX_DOCKERFILE = """
FROM alpine:3.20

RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    curl \
    wget \
    bind-tools \
    hydra \
    jq \
    python3 \
    py3-pip \
    git \
    bash

# Install nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.deb \
    && apk add --no-cache --allow-untrusted nuclei_3.3.9_linux_amd64.deb \
    && rm nuclei_3.3.9_linux_amd64.deb

WORKDIR /workspace
ENTRYPOINT ["/bin/sh"]
"""


@dataclass
class SandboxConfig:
    """Configuration for a sandbox execution environment."""

    image: str = _SANDBOX_IMAGE
    memory_mb: int = 512
    cpu_limit: float = 0.5
    timeout_seconds: int = 300
    network_enabled: bool = False
    read_only_root: bool = True
    temp_dir: str | None = None
    mounts: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxResult:
    """Result from a sandboxed tool execution."""

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int


class SandboxError(RuntimeError):
    """Raised when sandbox execution fails."""


class SandboxExecutor:
    """Manages Docker-based sandbox execution of security tools.

    Each tool invocation creates a temporary container that is destroyed
    after execution. Supports resource limits, timeouts, and network isolation.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()

    async def execute(self, cmd: list[str], cwd: str | None = None) -> SandboxResult:
        """Execute a command inside a sandbox Docker container."""
        started = time.monotonic()

        # Build docker run arguments
        docker_args = [
            "docker", "run", "--rm",
            "-i",
            "--network", "none" if not self.config.network_enabled else "bridge",
            "--memory", f"{self.config.memory_mb}m",
            "--cpus", str(self.config.cpu_limit),
            "--workdir", "/workspace",
        ]

        if self.config.read_only_root:
            docker_args.extend(["--read-only", "--tmpfs", "/tmp:size=64M"])

        # Mount volumes
        temp_host_dir = None
        if self.config.mounts:
            for host_path, container_path in self.config.mounts.items():
                docker_args.extend(["-v", f"{host_path}:{container_path}"])
        elif cwd:
            host_cwd = str(Path(cwd).resolve())
            temp_host_dir = host_cwd
            docker_args.extend(["-v", f"{host_cwd}:/workspace"])

        # Create temp dir for shared output if no mounts
        if not temp_host_dir and not self.config.mounts:
            temp_host_dir = tempfile.mkdtemp(prefix="secmind-sandbox-")
            docker_args.extend(["-v", f"{temp_host_dir}:/workspace"])

        docker_args.append(self.config.image)
        docker_args.extend(cmd)

        process = await asyncio.create_subprocess_exec(
            *docker_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.timeout_seconds
            )
        except TimeoutError:
            process.kill()
            await process.communicate()
            raise SandboxError(
                f"Sandbox execution timed out after {self.config.timeout_seconds}s"
            ) from None

        duration = int((time.monotonic() - started) * 1000)

        return SandboxResult(
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=process.returncode or 0,
            duration_ms=duration,
        )

    async def ensure_image(self) -> bool:
        """Check if the sandbox image exists; if not, build it.

        Returns True if the image is available (either found or built).
        """
        check = await asyncio.create_subprocess_exec(
            "docker", "images", "-q", self.config.image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await check.communicate()
        if out.decode(errors="replace").strip():
            return True

        raise SandboxError(
            f"Sandbox image '{self.config.image}' not found. "
            f"Build it with:\n\n"
            f"cat <<'DOCKERFILE' | docker build -t {self.config.image} -\n"
            f"{_SANDBOX_DOCKERFILE}\n"
            f"DOCKERFILE\n"
        )

    @staticmethod
    def parse_nmap_output(stdout: str) -> list[dict[str, Any]]:
        """Parse nmap output into structured results."""
        results = []
        for line in stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].isdigit():
                results.append({
                    "port": int(parts[0]),
                    "state": parts[1] if len(parts) > 1 else "unknown",
                    "service": parts[2] if len(parts) > 2 else "",
                })
        return results

    @staticmethod
    def parse_nuclei_json(stdout: str) -> list[dict[str, Any]]:
        """Parse nuclei JSON-line output into structured results."""
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append({
                    "template": obj.get("template-id", ""),
                    "name": obj.get("info", {}).get("name", ""),
                    "severity": obj.get("info", {}).get("severity", ""),
                    "matched": obj.get("matched-at", ""),
                    "extracted_results": obj.get("extracted-results", []),
                })
            except json.JSONDecodeError:
                continue
        return results

    @staticmethod
    def parse_gobuster_json(stdout: str) -> list[dict[str, Any]]:
        """Parse gobuster JSON-line output into structured results."""
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append({
                    "path": obj.get("path", ""),
                    "status": obj.get("status", 0),
                    "size": obj.get("size", 0),
                })
            except json.JSONDecodeError:
                continue
        return results
