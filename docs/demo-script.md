# Product Demo Script

Use this script for a 5 to 7 minute demo of AI Security Sandbox as a model-risk review and secure agent operations product.

## One-line setup

AI Security Sandbox helps security and platform teams register AI agents, score model and tool risk, run red-team evals, enforce OPA release gates, monitor runs, and export audit evidence.

## Demo persona

- Reviewer: security engineering or AI governance lead
- Agent owner: product team deploying a network-capable support or research agent
- SOC analyst: responder validating runtime evidence and containment options

## Demo flow

### 1. Register a risky agent

Show the product workflow API or UI path for creating an agent registration.

Example agent:

```json
{
  "display_name": "Customer Support Research Agent",
  "business_purpose": "Research customer support tickets and summarize sensitive account issues for operations review.",
  "owners": [
    {
      "name": "Security Reviewer",
      "email": "security@example.com",
      "team": "AI Governance"
    }
  ],
  "model": {
    "provider": "azure-openai",
    "model": "gpt-4o",
    "max_tokens_per_run": 50000,
    "stores_prompts": false,
    "stores_outputs": false
  },
  "tools": [
    {
      "name": "http_get",
      "description": "Fetch approved support knowledge sources.",
      "can_read_data": true,
      "can_write_data": false,
      "can_call_external_network": true,
      "requires_human_approval": false
    }
  ],
  "data_classes": ["confidential", "pii"],
  "allowed_egress_fqdns": ["support.example.com"],
  "prompt_injection_defenses": ["prompt_shield", "retrieved_content_rescan"],
  "human_approval_actions": ["external_post", "customer_record_update"],
  "environment": "prod"
}
```

Narration:

> We are not approving an agent by vibes. The owner declares model, tools, data classes, egress, controls, and business purpose up front.

### 2. Show generated risk profile

Show the risk score, tier, and mapped controls.

Narration:

> The system maps risk factors to OWASP LLM, NIST AI RMF, and ISO 42001 so reviewers get an audit-friendly decision record, not just a generic checklist.

Key points to call out:

- Sensitive data raises impact.
- Network-capable tools raise egress and SSRF concerns.
- Prompt-injection defenses reduce risk but do not erase it.
- Human approval actions reduce autonomous agency risk.

### 3. Run the red-team/eval pack

Trigger the red-team route for the registered agent.

Narration:

> The eval pack checks common agent failure modes before production: prompt injection, unsafe egress, unauthorized tool use, sensitive data leakage, and human-approval bypass.

Good demo moment:

- Show one passing case from the prompt-injection defense.
- Show one warning or failure when egress or approval controls are missing.

### 4. Produce go/no-go review

Show the generated review decision.

Decision story:

- Low risk + passing evals: `go`
- Medium risk or non-critical findings: `conditional_go`
- High risk or critical eval failure: `no_go`

Narration:

> This gives security a repeatable release decision with required mitigations and reviewer notes.

### 5. Show OPA deployment policy

Open the generated deployment policy bundle and `policies/product_workflow.rego`.

Narration:

> The review is not just documentation. The go/no-go decision becomes a policy gate for deployment.

Call out:

- `deploy_allowed`
- `requires_security_exception`
- `deny` reasons
- Capability manifest and egress allowlist

### 6. Monitor in SOC console

Show the SOC console or describe the available runtime evidence.

Narration:

> After deployment, the SOC sees agent runs, denials, approvals, prompt-injection signals, egress attempts, and kill-switch events in one timeline.

SOC questions answered:

- Who owns this agent?
- What was it allowed to do?
- What did it actually do?
- Which policy blocked or allowed the action?
- Can we stop it quickly?

### 7. Export audit evidence

Export the evidence payload for the agent.

Narration:

> At audit time, the team can export registration, risk profile, red-team results, review decision, deployment policy, and control mapping as one evidence package.

## Closing line

AI Security Sandbox turns AI agent approval from a spreadsheet into an enforceable lifecycle: register, evaluate, approve, deploy, monitor, and prove.