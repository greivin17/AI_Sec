package agent.product_workflow

default deploy_allowed = false
default requires_security_exception = false

deploy_allowed {
    input.review_decision == "go"
    not has_critical_eval_failure
    not has_high_or_critical_risk
}

requires_security_exception {
    input.review_decision == "conditional_go"
    not has_critical_eval_failure
}

has_high_or_critical_risk {
    input.risk_tier == "high"
}

has_high_or_critical_risk {
    input.risk_tier == "critical"
}

has_critical_eval_failure {
    result := input.red_team_results[_]
    result.status == "fail"
    result.critical == true
}

deny["review_decision_no_go"] {
    input.review_decision == "no_go"
}

deny["critical_red_team_failure"] {
    has_critical_eval_failure
}

deny["risk_tier_blocks_deploy"] {
    has_high_or_critical_risk
}

deny["missing_owner"] {
    count(input.owners) == 0
}

deny["missing_business_purpose"] {
    input.business_purpose == ""
}

release_summary := {
    "deploy_allowed": deploy_allowed,
    "requires_security_exception": requires_security_exception,
    "denial_reasons": deny,
}
