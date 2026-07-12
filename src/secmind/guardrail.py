from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from secmind.schemas import RiskLevel, ToolManifest


class GuardrailAction(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class GuardrailDecision:
    action: GuardrailAction
    risk_level: RiskLevel
    policy_ids: tuple[str, ...]
    reason: str


class Guardrail:
    """Rules-first policy engine. Model output can never lower a manifest risk level."""

    BLOCKED_TERMS = {
        "credential_theft",
        "persistence",
        "destructive",
        "ransomware",
        "wipe_disk",
        "disable_security",
    }

    def evaluate(
        self,
        manifest: ToolManifest,
        parameters: dict[str, Any],
        autonomy_policy: str,
    ) -> GuardrailDecision:
        serialized = str(parameters).lower()
        if manifest.risk_level >= RiskLevel.R3 or any(term in serialized for term in self.BLOCKED_TERMS):
            return GuardrailDecision(
                GuardrailAction.DENY,
                RiskLevel.R3,
                ("POL-R3-DENY",),
                "Destructive, credential, persistence, or out-of-scope actions are prohibited.",
            )
        if autonomy_policy == "approval_all" or manifest.risk_level == RiskLevel.R2:
            return GuardrailDecision(
                GuardrailAction.REQUIRE_APPROVAL,
                max(manifest.risk_level, RiskLevel.R2),
                ("POL-R2-HITL",),
                "The operation requires explicit operator approval.",
            )
        return GuardrailDecision(
            GuardrailAction.ALLOW,
            manifest.risk_level,
            ("POL-R0-R1-AUTO",),
            "Read-only operation is allowed inside the controlled workspace.",
        )
