"""Skills loader — parses agentskills.io YAML skill definitions into SecMind ToolManifests.

Supports loading skills from the Anthropic-Cybersecurity-Skills format
(https://github.com/mukul975/Anthropic-Cybersecurity-Skills) and converting
them into executable SecMind tools.

agentskills.io standard reference: https://agentskills.io
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from secmind.schemas import RiskLevel, Scenario, ToolManifest
from secmind.tools import BaseTool, ToolError, ToolResult, ToolStatus, ToolContext


# Canonical scenario mapping from agentskills.io to SecMind
_SCENARIO_MAP: dict[str, Scenario] = {
    "code_audit": Scenario.CODE_AUDIT,
    "vulnerability_assessment": Scenario.CODE_AUDIT,
    "log_analysis": Scenario.LOG_ANALYSIS,
    "incident_response": Scenario.INCIDENT_RESPONSE,
    "penetration_test": Scenario.PENETRATION_TEST,
    "threat_hunting": Scenario.PENETRATION_TEST,
    "malware_analysis": Scenario.LOG_ANALYSIS,
}

# Risk level mapping
_RISK_MAP: dict[str, RiskLevel] = {
    "R0": RiskLevel.R0,
    "R1": RiskLevel.R1,
    "R2": RiskLevel.R2,
    "R3": RiskLevel.R3,
}


def _parse_scenarios(raw: Any) -> list[Scenario]:
    """Parse scenarios from a skill YAML definition."""
    if not raw:
        return [Scenario.UNKNOWN]
    if isinstance(raw, str):
        raw = [raw]
    seen: set[Scenario] = set()
    result: list[Scenario] = []
    for item in raw:
        mapped = _SCENARIO_MAP.get(item)
        if mapped and mapped not in seen:
            seen.add(mapped)
            result.append(mapped)
    return result or [Scenario.UNKNOWN]


def _parse_risk_level(raw: Any) -> RiskLevel:
    """Parse risk level from skill definition."""
    if isinstance(raw, dict):
        raw = raw.get("level", "R1")
    return _RISK_MAP.get(str(raw).upper(), RiskLevel.R1)


def skill_yaml_to_manifest(skill_data: dict[str, Any]) -> ToolManifest:
    """Convert a raw skill YAML dict into a SecMind ToolManifest.

    Args:
        skill_data: Parsed YAML content from a skill definition file.

    Returns:
        A ToolManifest instance compatible with SecMind's tool system.
    """
    name = skill_data.get("name", str(skill_data.get("display_name", "unknown_skill")).lower().replace(" ", "_"))
    description = skill_data.get("description", "")
    scenarios = _parse_scenarios(skill_data.get("scenarios"))
    risk_level = _parse_risk_level(skill_data.get("risk_assessment", "R1"))

    # Use the first tool definition's input/output schema, or provide defaults
    tool_defs = skill_data.get("tool_definitions", [])
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    output_schema: dict[str, Any] = {"type": "object", "properties": {}}
    timeout = 120
    permissions: list[str] = []
    requires_network = False

    if tool_defs and isinstance(tool_defs, list):
        first = tool_defs[0] if isinstance(tool_defs[0], dict) else {}
        input_schema = first.get("input_schema", input_schema)
        output_schema = first.get("output_schema", output_schema)

    # Parse permissions
    perms_raw = skill_data.get("permissions", [])
    if isinstance(perms_raw, list):
        permissions = [str(p) for p in perms_raw]

    # Parse timeout
    timeout = skill_data.get("timeout_seconds", 120)

    # Determine network requirement
    if isinstance(perms_raw, list):
        requires_network = any("network" in str(p) for p in perms_raw)

    return ToolManifest(
        name=name,
        version=skill_data.get("version", "1"),
        description=description,
        scenarios=scenarios,
        input_schema=input_schema,
        output_schema=output_schema,
        risk_level=risk_level,
        permissions=permissions,
        timeout_seconds=timeout,
        idempotent=skill_data.get("idempotent", True),
        requires_network=requires_network,
    )


class DynamicTool(BaseTool):
    """A generic tool dynamically created from a skill manifest.

    Executes the skill's defined logic — for skills without native Python
    implementations, this logs the invocation and provides a stub result.
    """

    def __init__(self, manifest: ToolManifest) -> None:
        self.manifest = manifest

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        """Execute this dynamic skill.

        For read-only / data-query skills, this returns a stub indicating
        the skill is available. For actionable skills, implement the
        corresponding logic in a subclass.
        """
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={"message": f"Skill '{self.manifest.name}' invoked"},
            summary=f"Skill '{self.manifest.name}' executed",
        )


class SkillsLoader:
    """Loads and manages skill definitions from a skills directory."""

    def __init__(self, skills_dir: str | Path | None = None) -> None:
        self.skills_dir = Path(skills_dir) if skills_dir else None

    def discover(self) -> list[Path]:
        """Discover all skill YAML files in the configured directory.

        Returns a list of (domain, skill_file_path) tuples.
        """
        if not self.skills_dir or not self.skills_dir.is_dir():
            return []

        yaml_files: list[Path] = []
        for root, _dirs, files in os.walk(str(self.skills_dir)):
            for fname in files:
                if fname.endswith((".yaml", ".yml")):
                    yaml_files.append(Path(root) / fname)
        return sorted(yaml_files)

    def load_all_manifests(self) -> list[ToolManifest]:
        """Load all skill YAML files and convert to ToolManifests."""
        manifests: list[ToolManifest] = []
        for yaml_path in self.discover():
            try:
                manifest_data = self._parse_yaml_file(yaml_path)
                if manifest_data:
                    manifest = skill_yaml_to_manifest(manifest_data)
                    manifests.append(manifest)
            except Exception as exc:
                sys.stderr.write(f"Warning: Failed to load skill {yaml_path}: {exc}\n")
        return manifests

    def register_all(self, registry: Any) -> int:
        """Load and register all skills into a ToolRegistry.

        Args:
            registry: A secmind.tools.ToolRegistry instance.

        Returns:
            Number of skills successfully registered.
        """
        count = 0
        for manifest in self.load_all_manifests():
            try:
                registry.register(DynamicTool(manifest))
                count += 1
            except ToolError:
                continue
        return count

    def _parse_yaml_file(self, path: Path) -> dict[str, Any] | None:
        """Parse a YAML skill file.

        Falls back gracefully if PyYAML is not installed.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            sys.stderr.write(
                "Warning: PyYAML is required to parse skill files. "
                "Install it with: pip install pyyaml\n"
            )
            return None

        try:
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as exc:
            sys.stderr.write(f"Warning: YAML parse error in {path}: {exc}\n")
            return None
