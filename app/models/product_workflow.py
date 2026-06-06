"""Models for the productized agent risk review workflow."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    PAYMENT = "payment"
    SECRETS = "secrets"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewDecision(str, Enum):
    GO = "go"
    CONDITIONAL_GO = "conditional_go"
    NO_GO = "no_go"


class EvalStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class ControlFramework(str, Enum):
    OWASP_LLM = "owasp_llm"
    NIST_AI_RMF = "nist_ai_rmf"
    ISO_42001 = "iso_42001"


class OwnerContact(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=320)
    team: str = Field(..., min_length=1, max_length=120)


class ToolDeclaration(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str = Field(default="", max_length=512)
    can_read_data: bool = True
    can_write_data: bool = False
    can_call_external_network: bool = False
    requires_human_approval: bool = False


class ModelDeclaration(BaseModel):
    provider: str = Field(..., min_length=1, max_length=80)
    model: str = Field(..., min_length=1, max_length=120)
    deployment: str | None = Field(default=None, max_length=120)
    max_tokens_per_run: int = Field(default=50_000, ge=1, le=5_000_000)
    stores_prompts: bool = False
    stores_outputs: bool = False


class AgentRegistrationRequest(BaseModel):
    agent_id: str = Field(default_factory=lambda: f"agent-{uuid.uuid4().hex[:10]}")
    display_name: str = Field(..., min_length=1, max_length=120)
    business_purpose: str = Field(..., min_length=10, max_length=2048)
    owners: list[OwnerContact] = Field(..., min_length=1, max_length=10)
    model: ModelDeclaration
    tools: list[ToolDeclaration] = Field(default_factory=list, max_length=50)
    data_classes: list[DataClass] = Field(default_factory=lambda: [DataClass.INTERNAL])
    allowed_egress_fqdns: list[str] = Field(default_factory=list, max_length=100)
    prompt_injection_defenses: list[str] = Field(default_factory=list, max_length=20)
    human_approval_actions: list[str] = Field(default_factory=list, max_length=50)
    environment: str = Field(default="dev", max_length=40)

    @field_validator("allowed_egress_fqdns")
    @classmethod
    def validate_egress(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            host = value.strip().lower()
            if not host:
                continue
            if "/" in host or "://" in host:
                raise ValueError(
                    "allowed_egress_fqdns must contain hostnames, not URLs"
                )
            cleaned.append(host)
        return cleaned


class ControlMapping(BaseModel):
    framework: ControlFramework
    control_id: str
    title: str
    rationale: str


class RiskFactor(BaseModel):
    name: str
    severity: RiskTier
    score: int = Field(..., ge=0, le=100)
    rationale: str
    mappings: list[ControlMapping] = Field(default_factory=list)
    mitigation: str


class RiskProfile(BaseModel):
    agent_id: str
    score: int = Field(..., ge=0, le=100)
    tier: RiskTier
    factors: list[RiskFactor]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RedTeamCase(BaseModel):
    case_id: str
    title: str
    attack_type: str
    expected_control: str
    critical: bool = False


class RedTeamResult(BaseModel):
    case: RedTeamCase
    status: EvalStatus
    evidence: str
    remediation: str | None = None


class RedTeamRun(BaseModel):
    agent_id: str
    run_id: str = Field(default_factory=lambda: f"eval-{uuid.uuid4().hex[:10]}")
    results: list[RedTeamResult]
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GoNoGoReview(BaseModel):
    agent_id: str
    decision: ReviewDecision
    risk_profile: RiskProfile
    red_team_run: RedTeamRun | None = None
    required_mitigations: list[str] = Field(default_factory=list)
    reviewer_notes: str = ""
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeploymentPolicyBundle(BaseModel):
    agent_id: str
    capability_manifest: dict[str, Any]
    opa_input_contract: dict[str, Any]
    recommended_feature_flags: dict[str, bool]
    release_gate: ReviewDecision


class EvidenceExport(BaseModel):
    agent_id: str
    registration: AgentRegistrationRequest
    risk_profile: RiskProfile
    red_team_run: RedTeamRun | None = None
    review: GoNoGoReview | None = None
    deployment_policy: DeploymentPolicyBundle | None = None
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentProductRecord(BaseModel):
    registration: AgentRegistrationRequest
    risk_profile: RiskProfile
    red_team_run: RedTeamRun | None = None
    review: GoNoGoReview | None = None
