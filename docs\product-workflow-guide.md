# Product Workflow Guide

This guide describes the generated model-risk review workflow for AI Security Sandbox.

## Goal

The workflow converts the sandbox from a reference architecture into a product motion for AI agent governance:

1. Register agent metadata.
2. Generate risk mappings.
3. Run a red-team/eval pack.
4. Produce a go/no-go review.
5. Generate OPA and capability policy artifacts.
6. Monitor production runs.
7. Export evidence.

## Backend Module

The backend workflow lives in:

- `app/models/product_workflow.py`
- `app/product_workflow.py`

`app/main.py` mounts the router:

```python
from product_workflow import router as product_workflow_router

app.include_router(product_workflow_router)
```

## Persistence

Set these environment variables to persist agent review records to Azure Blob Storage:

| Variable | Purpose |
|---|---|
| `PRODUCT_WORKFLOW_STORAGE_ACCOUNT` | Storage account that holds model-risk review records. |
| `PRODUCT_WORKFLOW_CONTAINER` | Container name; defaults to `agent-risk-registry`. |

When `PRODUCT_WORKFLOW_STORAGE_ACCOUNT` is empty, the workflow uses in-memory state for local demos and unit tests.

## Example Registration Request

```json
{
  "agent_id": "finance-research-agent",
  "display_name": "Finance Research Agent",
  "business_purpose": "Research public company filings and summarize risk signals for analyst review.",
  "owners": [
    {
      "name": "Ava Patel",
      "email": "ava.patel@example.com",
      "team": "Financial Risk"
    }
  ],
  "model": {
    "provider": "azure-openai",
    "model": "gpt-4.1",
    "deployment": "gpt-4-1-prod",
    "max_tokens_per_run": 100000,
    "stores_prompts": false,
    "stores_outputs": false
  },
  "tools": [
    {
      "name": "file_read",
      "description": "Read uploaded source documents.",
      "can_read_data": true,
      "can_write_data": false,
      "can_call_external_network": false,
      "requires_human_approval": false
    },
    {
      "name": "http_get",
      "description": "Fetch public filings from approved APIs.",
      "can_read_data": true,
      "can_write_data": false,
      "can_call_external_network": true,
      "requires_human_approval": false
    },
    {
      "name": "file_write",
      "description": "Write analyst summary reports.",
      "can_read_data": false,
      "can_write_data": true,
      "can_call_external_network": false,
      "requires_human_approval": false
    }
  ],
  "data_classes": ["internal", "confidential"],
  "allowed_egress_fqdns": ["api.sec.gov"],
  "prompt_injection_defenses": ["prompt_shield", "retrieved_content_scan"],
  "human_approval_actions": ["http_post"],
  "environment": "prod"
}
```

## Example API Flow

```bash
curl -X POST "$APIM_URL/sandbox/product/agents" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @agent-registration.json

curl "$APIM_URL/sandbox/product/agents/finance-research-agent/risk" \
  -H "Authorization: Bearer $TOKEN"

curl -X POST "$APIM_URL/sandbox/product/agents/finance-research-agent/red-team" \
  -H "Authorization: Bearer $TOKEN"

curl -X POST "$APIM_URL/sandbox/product/agents/finance-research-agent/review" \
  -H "Authorization: Bearer $TOKEN"

curl "$APIM_URL/sandbox/product/agents/finance-research-agent/deployment-policy" \
  -H "Authorization: Bearer $TOKEN"

curl "$APIM_URL/sandbox/product/agents/finance-research-agent/evidence" \
  -H "Authorization: Bearer $TOKEN"
```

## Risk Mapping

The first version maps agent declarations to these frameworks:

| Risk | OWASP LLM | NIST AI RMF | ISO 42001 |
|---|---|---|---|
| Prompt injection | LLM01 | MEASURE 2.7 | A.8.2 |
| Sensitive data | LLM02 | MAP 2.3 | A.7.4 |
| Unsafe output/action handling | LLM05 | MANAGE 2.3 | A.8.2 |
| Excessive agency | LLM08 | MANAGE 2.3 | A.6.2 |
| Unbounded consumption | LLM10 | MEASURE 2.7 | A.8.2 |

## Red-Team Pack

The initial pack is deterministic. It does not call a live model. It verifies that required controls are declared before the agent can progress:

- instruction override prompt injection
- sensitive data exfiltration
- unauthorized tool invocation
- egress policy bypass
- token bomb and runaway loop

For production, replace or extend this with live evals that execute controlled adversarial prompts against the deployed sandbox.

## Deployment Gate

Add `policies/product_workflow.rego` to the OPA bundle. It gives a release gate that can be called before production deployment:

- `deploy_allowed`: true only for `go` reviews without high risk or critical eval failures.
- `requires_security_exception`: true for `conditional_go` reviews without critical failures.
- `denial_reasons`: structured list of blockers.

## Next Production Hardening Tasks

1. Persist agent records in durable storage.
2. Connect review decisions to Entra groups and approval workflows.
3. Emit product workflow actions as `AuditEvent` records.
4. Add frontend views for registry, risk profile, eval results, go/no-go, and evidence export.
5. Add Sentinel workbook panels for review decisions and release gates.
6. Run live prompt-injection and tool-abuse tests in an isolated staging environment.
7. Require a successful product workflow gate before deployment jobs push production policy bundles.
