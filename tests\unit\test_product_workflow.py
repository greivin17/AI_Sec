from models.product_workflow import (
    AgentRegistrationRequest,
    DataClass,
    ModelDeclaration,
    OwnerContact,
    ReviewDecision,
    ToolDeclaration,
)
from product_workflow import (
    build_deployment_policy,
    generate_risk_profile,
    produce_review,
    register_agent,
    run_red_team_pack,
)


def _owner() -> OwnerContact:
    return OwnerContact(
        name="Security Owner",
        email="security@example.com",
        team="AI Platform",
    )


def test_low_risk_agent_gets_go_review():
    registration = AgentRegistrationRequest(
        agent_id="test-low-risk-agent",
        display_name="Low Risk Agent",
        business_purpose="Summarize public support documentation for internal teams.",
        owners=[_owner()],
        model=ModelDeclaration(provider="azure-openai", model="gpt-4.1"),
        tools=[
            ToolDeclaration(name="file_read", can_read_data=True),
            ToolDeclaration(name="openai_call", can_read_data=True),
        ],
        data_classes=[DataClass.PUBLIC],
        prompt_injection_defenses=["prompt_shield", "retrieved_content_scan"],
    )

    record = register_agent(registration)
    red_team = run_red_team_pack(record.registration.agent_id)
    review = produce_review(record.registration.agent_id)
    policy = build_deployment_policy(record.registration.agent_id)

    assert record.risk_profile.tier == "low"
    assert all(result.status == "pass" for result in red_team.results)
    assert review.decision == ReviewDecision.GO
    assert policy.release_gate == ReviewDecision.GO
    assert policy.recommended_feature_flags["agent-test-low-risk-agent-enabled"] is True


def test_sensitive_network_agent_blocks_without_controls():
    registration = AgentRegistrationRequest(
        agent_id="test-risky-agent",
        display_name="Risky Agent",
        business_purpose="Analyze confidential source data and call external tools.",
        owners=[_owner()],
        model=ModelDeclaration(
            provider="azure-openai",
            model="gpt-4.1",
            max_tokens_per_run=500000,
        ),
        tools=[
            ToolDeclaration(name="file_read", can_read_data=True),
            ToolDeclaration(name="http_get", can_call_external_network=True),
            ToolDeclaration(name="file_write", can_write_data=True),
        ],
        data_classes=[DataClass.CONFIDENTIAL, DataClass.PII],
    )

    record = register_agent(registration)
    profile = generate_risk_profile(registration)
    red_team = run_red_team_pack(record.registration.agent_id)
    review = produce_review(record.registration.agent_id)

    assert profile.tier in {"high", "critical"}
    assert any(result.status == "fail" for result in red_team.results)
    assert review.decision == ReviewDecision.NO_GO
    assert review.required_mitigations
