# Product Demo Story

## One-line Positioning

AI Security Sandbox makes enterprise AI agents approvable, observable, and killable before they receive production access.

## Demo Audience

- CISO, head of AI governance, or security architecture leader
- SOC manager or detection engineer
- Platform team deploying Azure OpenAI agents
- Application owner asking for production approval

## Narrative

1. A business team wants to deploy a new AI agent.
2. Security requires a model-risk review before production credentials are granted.
3. The agent owner declares the model, tools, data classes, owners, egress, and business purpose.
4. The sandbox generates a risk profile mapped to OWASP LLM, NIST AI RMF, and ISO 42001.
5. The red-team pack finds missing controls or confirms the declared safeguards.
6. The reviewer gets a go/no-go decision with required mitigations.
7. The deployment policy bundle turns the review into OPA and capability controls.
8. Runtime activity is monitored in the SOC console and Azure Sentinel.
9. The evidence export gives auditors a point-in-time record of the review, evals, policy, and operational controls.

## Live Demo Flow

### 1. Register a Risky Agent

Open the **Review** tab and submit an agent with:

- confidential or PII data
- a network-capable tool
- no prompt-injection defenses
- no egress allowlist

Expected result: risk profile returns high or critical risk.

### 2. Run Red-team Pack

Click **Red-team**.

Expected result: prompt injection, data exfiltration, and egress bypass checks fail.

### 3. Produce No-go Review

Click **Review**.

Expected result: `no_go` decision with concrete mitigations.

### 4. Add Controls

Update the agent declaration:

- add `prompt_shield`
- add `retrieved_content_scan`
- add exact FQDN allowlist
- mark high-impact tools as requiring approval
- lower token budget if needed

Re-register under a new `agent_id`, then rerun the review.

Expected result: decision improves to `go` or `conditional_go`.

### 5. Generate Deployment Policy

Click **Policy**.

Expected result: the generated bundle contains allowed tools, data classes, egress FQDNs, high-risk actions, feature flags, and OPA input contract.

### 6. Export Evidence

Click **Evidence**.

Expected result: downloadable JSON payload showing the declaration, risk profile, eval result, review decision, and deployment policy.

### 7. Monitor Runtime

Switch to **Chat** and run an approved scenario.

Expected result: run IDs, correlation IDs, and audit events can be traced through the SOC console, Log Analytics, WORM audit storage, and Sentinel.

## Value Proposition

The customer moves from informal AI review meetings to an enforceable release process:

- Every agent has an owner and declared purpose.
- Every production agent has a documented risk decision.
- Every tool and egress path becomes policy.
- Every run can be investigated.
- Every unsafe capability can be shut down.

## Monetization Angle

Package this as an Azure Marketplace solution accelerator plus enterprise add-ons:

- managed policy packs by industry
- red-team scenario library
- evidence exports for auditors
- Sentinel workbook templates
- private deployment support
- annual review workflow and retesting automation

