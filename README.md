# AI Security Sandbox

AI Security Sandbox is an Azure-native control plane for approving, deploying, monitoring, and auditing AI agents.

It turns agent security from a one-time checklist into an operational workflow:

1. Register an agent.
2. Declare its model, tools, data classes, egress, owners, and business purpose.
3. Auto-generate a risk profile mapped to OWASP LLM, NIST AI RMF, and ISO 42001.
4. Run a repeatable red-team and eval pack.
5. Produce a go/no-go review.
6. Deploy with OPA and capability policies.
7. Monitor runs in the SOC console.
8. Export audit evidence for security, compliance, and model-risk review.

## Product Positioning

Most AI security tools focus on one layer: prompt filtering, model scanning, red teaming, or runtime logging. This project combines those controls into an approval and runtime control plane for teams building agents on Azure.

The core buyer is a security, AI governance, or platform engineering team that needs to answer:

- Which agents are approved for production?
- What data, tools, models, and network destinations can each agent use?
- What risks were found before deployment?
- Which controls block prompt injection, data leakage, excessive agency, and unsafe egress?
- Can the SOC trace, contain, and kill unsafe agent behavior?
- Can the team export evidence for NIST AI RMF, ISO 42001, and OWASP LLM controls?

## Architecture

```text
User or Reviewer
      |
      v
Frontend SOC Console
      |
      v
Azure API Management
  - JWT validation
  - rate limits
  - signed identity headers
      |
      v
FastAPI Orchestrator
  - agent registry
  - model-risk workflow
  - red-team/eval runner
  - go/no-go review
  - run registry
  - kill switches
      |
      +--> OPA policy sidecar
      |      - capability allowlists
      |      - egress policy
      |      - high-risk approval gates
      |      - deployment release gates
      |
      +--> Ephemeral Agent Runner
      |      - isolated workspace
      |      - token budget
      |      - file and network sandbox
      |
      +--> Azure Monitor, Log Analytics, Sentinel
      |      - structured events
      |      - detections
      |      - SOC timelines
      |
      +--> WORM Audit Storage
             - immutable JSONL evidence
```

## Core Security Controls

| Control | Implementation |
|---|---|
| Identity boundary | Entra ID, APIM JWT validation, signed gateway headers |
| Least privilege | Managed identities and per-agent capability manifests |
| Policy-as-code | OPA Rego policies for tool, path, egress, and release gates |
| Prompt-injection defense | Deterministic and heuristic scans before execution |
| Human approval | High-risk actions can require HITL approval |
| Sandboxing | Ephemeral workspace, path canonicalization, quotas, and safe file handling |
| Runtime containment | Per-agent egress allowlists, token budgets, time limits, kill switches |
| Audit evidence | Structured audit events to Log Analytics and WORM append blobs |
| SOC operations | Sentinel detections, timeline queries, alert triage, and kill switch workflows |
| Compliance support | DSAR metadata, retention policy, evidence export, framework mappings |

## Product Workflow API

The generated product workflow module adds a self-contained API surface:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/product/agents` | Register an agent and generate its initial risk profile |
| `GET` | `/product/agents` | List registered agents |
| `GET` | `/product/agents/{agent_id}/risk` | View risk profile and control mappings |
| `POST` | `/product/agents/{agent_id}/red-team` | Run deterministic red-team/eval pack |
| `POST` | `/product/agents/{agent_id}/review` | Produce go/no-go review |
| `GET` | `/product/agents/{agent_id}/deployment-policy` | Generate capability and OPA deployment policy bundle |
| `GET` | `/product/agents/{agent_id}/evidence` | Export model-risk review and audit evidence |

## Review Decision Model

| Decision | Meaning |
|---|---|
| `go` | Agent can be deployed with generated OPA and capability policies |
| `conditional_go` | Agent can proceed only after listed mitigations are accepted or completed |
| `no_go` | Agent should not be deployed until blocking risks are fixed |

The default gate is conservative:

- Critical eval failure means `no_go`.
- High risk score means `no_go`.
- Medium risk or non-critical failures mean `conditional_go`.
- Low risk with passing evals means `go`.

## Product Workflow Files

The product workflow is implemented by:

- `app/models/product_workflow.py`
- `app/product_workflow.py`
- `policies/product_workflow.rego`
- `docs/product-workflow-guide.md`
- `docs/product-demo-story.md`
- `frontend/src/components/ProductWorkflowConsole.tsx`

The FastAPI router is mounted from `app/main.py`:

```python
from product_workflow import router as product_workflow_router

app.include_router(product_workflow_router)
```

## Persistence

The product workflow uses Blob-backed persistence when configured:

- `PRODUCT_WORKFLOW_STORAGE_ACCOUNT`: storage account for agent risk records.
- `PRODUCT_WORKFLOW_CONTAINER`: optional container name, defaults to `agent-risk-registry`.

If no storage account is configured, the workflow falls back to in-memory state for local demos and unit tests.

## Release Gate

CI checks `policies/product_workflow.rego` with the rest of the OPA bundle. Production deployment should call the release gate before publishing policy bundles:

- `deploy_allowed`: true for approved low/medium-risk agents without critical eval failures.
- `requires_security_exception`: true for conditional approvals that need tracked acceptance.
- `deny`: structured blocker reasons for no-go releases.
