"""
ISO 42001 / NIST AI RMF governance module.

Responsibilities
----------------
1. Load static model cards for each agent type from
   ``app/governance/model_cards/{agent_type}.json``.
2. Expose a stable :class:`AIGovernanceMetadata` reference that
   :class:`AuditLogger` attaches to emitted events.
3. Maintain a deterministic control mapping matrix that links each OPA policy
   file and major in-process enforcement point to ISO 42001 and NIST AI RMF.
4. Issue HMAC-signed run attestations via :func:`build_run_attestation`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from capability_manifest import AGENT_CAPABILITIES
from models.ai_governance import AIGovernanceMetadata, ModelCard

logger = logging.getLogger(__name__)

_PKG_DIR = Path(__file__).resolve().parent
_APP_DIR = _PKG_DIR.parent
_MODEL_CARDS_DIR = _PKG_DIR / "model_cards"
_POLICIES_DIR = _APP_DIR.parent / "policies"


@lru_cache(maxsize=None)
def _load_all_model_cards() -> dict[str, ModelCard]:
    cards: dict[str, ModelCard] = {}
    if not _MODEL_CARDS_DIR.is_dir():
        logger.warning("Model cards directory missing: %s", _MODEL_CARDS_DIR)
        return cards
    for path in sorted(_MODEL_CARDS_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            card = ModelCard.model_validate(payload)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load model card {path.name}: {exc}"
            ) from exc
        cards[card.agent_type] = card
    return cards


def get_model_card(agent_type: str) -> ModelCard | None:
    """Return the model card for ``agent_type`` or ``None`` if not registered."""
    return _load_all_model_cards().get(agent_type)


def list_agent_types_with_cards() -> list[str]:
    return sorted(_load_all_model_cards().keys())


def build_governance_metadata(agent_type: str) -> AIGovernanceMetadata | None:
    """Compose the lightweight metadata pointer for an audit event."""
    card = get_model_card(agent_type)
    if card is None:
        return None
    return AIGovernanceMetadata(
        agent_type=card.agent_type,
        model_card_version=card.model_card_version,
        residual_risk_class=card.residual_risk_class,
        iso_42001_controls=list(card.iso_42001_controls),
        policy_bundle_hash=get_policy_bundle_hash(),
    )


def governance_reference(agent_type: str) -> str | None:
    """Return the compact ``agent_type@version/risk`` string or ``None``."""
    metadata = build_governance_metadata(agent_type)
    return metadata.reference() if metadata else None


_CONTROL_MAPPING: list[dict[str, Any]] = [
    {
        "enforcement_point": "capability_manifest.py",
        "description": "Per-agent-type allowlist of tools, FQDNs, and budgets.",
        "iso_42001_controls": ["8.2.1", "8.2.2"],
        "nist_ai_rmf": ["govern", "map"],
    },
    {
        "enforcement_point": "policies/agent_actions.rego",
        "description": (
            "Primary allow/deny/requires_approval decision per tool call."
        ),
        "iso_42001_controls": ["8.3.1", "8.4.2"],
        "nist_ai_rmf": ["map", "manage"],
    },
    {
        "enforcement_point": "policies/filesystem.rego",
        "description": (
            "Path traversal prevention, filename validation, "
            "content-type whitelist."
        ),
        "iso_42001_controls": ["8.4.1", "8.4.2"],
        "nist_ai_rmf": ["map", "measure"],
    },
    {
        "enforcement_point": "policies/network.rego",
        "description": (
            "Egress FQDN allowlist, SSRF prevention "
            "(metadata endpoint + private ranges)."
        ),
        "iso_42001_controls": ["8.4.1", "8.5.2"],
        "nist_ai_rmf": ["map", "manage"],
    },
    {
        "enforcement_point": "policies/secrets.rego",
        "description": (
            "Credential-leak detection in agent output "
            "(cloud keys, GitHub PATs, PEMs)."
        ),
        "iso_42001_controls": ["8.5.1"],
        "nist_ai_rmf": ["measure", "manage"],
    },
    {
        "enforcement_point": "policies/delegation.rego",
        "description": (
            "Agent-to-agent delegation: child type allowlist, scope subset, "
            "call-depth cap, cycle detection."
        ),
        "iso_42001_controls": ["8.2.1", "8.3.1"],
        "nist_ai_rmf": ["govern", "manage"],
    },
    {
        "enforcement_point": "policies/excessive_agency.rego",
        "description": (
            "LLM08 risk-score escalation to human approval for "
            "high-risk tool calls."
        ),
        "iso_42001_controls": ["8.3.1", "8.4.2"],
        "nist_ai_rmf": ["manage"],
    },
    {
        "enforcement_point": "policies/prompt_injection.rego",
        "description": (
            "Score-gated denial / approval routing for prompt-injection signals."
        ),
        "iso_42001_controls": ["8.2.2", "8.3.1"],
        "nist_ai_rmf": ["measure", "manage"],
    },
    {
        "enforcement_point": "policies/product_workflow.rego",
        "description": (
            "Release gate for registered agents based on go/no-go review, "
            "risk tier, red-team results, owners, and business purpose."
        ),
        "iso_42001_controls": ["8.2.1", "8.3.1", "9.2"],
        "nist_ai_rmf": ["govern", "map", "measure", "manage"],
    },
    {
        "enforcement_point": "app/prompt_shield.py + app/main.py regex layer",
        "description": (
            "Layered prompt-injection defense (regex + Azure AI Content "
            "Safety Prompt Shields + retrieved-content rescans)."
        ),
        "iso_42001_controls": ["8.2.2", "8.4.2"],
        "nist_ai_rmf": ["measure", "manage"],
    },
    {
        "enforcement_point": "app/sandbox.py",
        "description": (
            "Per-run ephemeral workspace; path canonicalization; "
            "magic-byte checks; quota enforcement."
        ),
        "iso_42001_controls": ["8.4.1", "8.4.2", "8.5.1"],
        "nist_ai_rmf": ["map", "manage"],
    },
    {
        "enforcement_point": "app/kill_switch.py",
        "description": (
            "Azure App Configuration feature flags; "
            "fail-closed on unreachability."
        ),
        "iso_42001_controls": ["9.2"],
        "nist_ai_rmf": ["manage"],
    },
    {
        "enforcement_point": "app/audit.py + Log Analytics + WORM blob",
        "description": (
            "Triple-sink structured audit trail "
            "(stdout, DCR, append-only blob)."
        ),
        "iso_42001_controls": ["9.2", "9.3"],
        "nist_ai_rmf": ["measure", "manage"],
    },
    {
        "enforcement_point": "app/main.py signed identity envelope",
        "description": "HMAC-signed per-request identity envelope from APIM.",
        "iso_42001_controls": ["8.2.1", "8.5.2"],
        "nist_ai_rmf": ["govern"],
    },
]


def get_control_mapping() -> list[dict[str, Any]]:
    """Return a deep-copied control mapping matrix."""
    return [dict(row) for row in _CONTROL_MAPPING]


@lru_cache(maxsize=1)
def get_policy_bundle_hash() -> str:
    """SHA-256 over the Rego and data files that constitute the policy bundle."""
    if not _POLICIES_DIR.is_dir():
        return "no-bundle"
    digest = hashlib.sha256()
    files: list[Path] = []
    files.extend(sorted(_POLICIES_DIR.glob("*.rego")))
    data_dir = _POLICIES_DIR / "data"
    if data_dir.is_dir():
        files.extend(sorted(data_dir.glob("*.json")))
    for path in files:
        try:
            with path.open("rb") as fh:
                digest.update(path.name.encode("utf-8"))
                digest.update(b"\x00")
                digest.update(fh.read())
                digest.update(b"\x00")
        except OSError as exc:
            logger.warning("Skipping policy file %s in bundle hash: %s", path, exc)
            continue
    return digest.hexdigest()


def derive_consent_status(classification_label: str | None) -> str:
    """Derive ISO/GDPR-friendly consent status from data classification."""
    if classification_label and classification_label.lower() in {
        "confidential",
        "restricted",
    }:
        return "required_and_verified"
    return "not_required"


def build_run_attestation(
    *,
    run_id: str,
    agent_type: str,
    extra: dict[str, Any] | None = None,
    signing_secret: str | None = None,
) -> dict[str, Any]:
    """Produce a signed attestation for a run's governance context."""
    card = get_model_card(agent_type)
    if card is None:
        raise ValueError(f"No model card registered for agent type {agent_type!r}")

    secret = signing_secret or os.environ.get("APIM_IDENTITY_SIGNING_SECRET", "")
    if not secret:
        raise ValueError(
            "APIM_IDENTITY_SIGNING_SECRET is not configured; cannot sign attestation"
        )

    capabilities = AGENT_CAPABILITIES.get(agent_type)
    payload: dict[str, Any] = {
        "schema": "ai-security-sandbox.attestation/v1",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "agent_type": agent_type,
        "model_card": {
            "version": card.model_card_version,
            "review_date": card.review_date.isoformat(),
            "model_name": card.model_name,
            "model_version": card.model_version,
            "model_provider": card.model_provider,
            "residual_risk_class": card.residual_risk_class.value,
            "iso_42001_controls": list(card.iso_42001_controls),
            "human_oversight_required": card.human_oversight_required,
        },
        "policy_bundle_hash": get_policy_bundle_hash(),
        "control_mapping_count": len(_CONTROL_MAPPING),
        "capabilities": (
            {
                "allowed_tools": list(capabilities.allowed_tools),
                "allowed_egress_fqdns": list(capabilities.allowed_egress_fqdns),
                "max_tokens_per_run": capabilities.max_tokens_per_run,
                "max_run_duration_seconds": capabilities.max_run_duration_seconds,
                "cost_budget_usd": capabilities.cost_budget_usd,
                "delegation_allowed": capabilities.delegation_allowed,
            }
            if capabilities is not None
            else None
        ),
    }
    if extra:
        payload["extra"] = extra

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}


def verify_run_attestation(
    attestation: dict[str, Any], *, signing_secret: str | None = None
) -> bool:
    """Recompute the HMAC and constant-time compare to the supplied signature."""
    secret = signing_secret or os.environ.get("APIM_IDENTITY_SIGNING_SECRET", "")
    if not secret:
        return False
    payload = attestation.get("payload")
    signature = attestation.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


__all__ = [
    "get_model_card",
    "list_agent_types_with_cards",
    "build_governance_metadata",
    "governance_reference",
    "get_control_mapping",
    "get_policy_bundle_hash",
    "derive_consent_status",
    "build_run_attestation",
    "verify_run_attestation",
]
