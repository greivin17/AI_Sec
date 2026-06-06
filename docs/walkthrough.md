# Two-Minute Product Walkthrough

Use this as the README walkthrough and as the voiceover for a short screen recording.

## Suggested GitHub About description

AI security workflow platform for registering agents, generating risk reviews, running red-team evals, enforcing OPA policies, and exporting audit evidence.

## 0:00-0:15 - Problem

AI agents are moving into production faster than security review processes can keep up. Teams need to know which agents are approved, what tools and data they can touch, what evals were run, and what evidence exists for audit.

Show:

- README opening section
- Product workflow routes table

## 0:15-0:40 - Register the agent

Create or display an agent registration that declares:

- Model provider and model name
- Tools and capability flags
- Data classes
- Egress destinations
- Owners
- Business purpose
- Prompt-injection defenses
- Human approval actions

Message:

> The product starts with an agent declaration, not a production incident.

## 0:40-1:05 - Generate risk and run evals

Show the risk profile and red-team/eval output.

Call out:

- OWASP LLM mapping
- NIST AI RMF mapping
- ISO 42001 mapping
- Prompt injection, unsafe egress, tool misuse, and sensitive data checks

Message:

> Risk review becomes repeatable and mapped to frameworks buyers already care about.

## 1:05-1:30 - Go/no-go release decision

Show the go/no-go review and required mitigations.

Message:

> The system produces a decision that security, engineering, and audit can all understand.

## 1:30-1:45 - Enforce with OPA

Show `policies/product_workflow.rego` and the deployment policy bundle.

Message:

> The review is enforceable. The deployment gate blocks risky agents and records structured deny reasons.

## 1:45-2:00 - SOC and evidence

Show SOC console concepts or evidence export route.

Message:

> After deployment, SOC can monitor agent behavior and export the evidence package for model-risk review, compliance, and incident response.

## Screenshot checklist

Add screenshots to the README when the UI is running:

1. Agent registration form or JSON payload
2. Risk profile with framework mappings
3. Red-team/eval results
4. Go/no-go review decision
5. OPA release gate output
6. SOC run timeline
7. Audit evidence export

## Recording checklist

For a polished demo recording:

- Keep the first screen on the actual product workflow, not a slide.
- Use one risky network-capable agent as the story thread.
- Show one blocked action or no-go result.
- End on exported evidence and the green CI badge.