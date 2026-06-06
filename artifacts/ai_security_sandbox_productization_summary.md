# AI Security Sandbox Productization Summary

## What Changed

- Resolved unresolved merge conflict markers in the downloaded repo copy by keeping the newer `HEAD` side.
- Replaced the README with product positioning for an Azure-native AI agent risk control plane.
- Added backend workflow models in `app/models/product_workflow.py`.
- Added backend workflow API in `app/product_workflow.py`.
- Wired the workflow router into `app/main.py`.
- Added optional Azure Blob persistence for agent review records:
  - `PRODUCT_WORKFLOW_STORAGE_ACCOUNT`
  - `PRODUCT_WORKFLOW_CONTAINER`
- Added OPA release gate policy in `policies/product_workflow.rego`.
- Added backend unit tests in `tests/unit/test_product_workflow.py`.
- Added a React SOC console workflow view in `frontend/src/components/ProductWorkflowConsole.tsx`.
- Updated `frontend/src/App.tsx` with top-level Review and Chat views.
- Added CI checks for the product workflow OPA gate.
- Added deploy workflow release gate using `.github/product-workflow-release.json`.
- Added product workflow and demo story docs.

## New Product Workflow

1. Register an agent.
2. Declare model, tools, data classes, egress, owners, and business purpose.
3. Auto-generate OWASP LLM, NIST AI RMF, and ISO 42001 risk mappings.
4. Run a deterministic red-team/eval pack.
5. Produce a go/no-go review.
6. Generate deployment policy and feature flag recommendations.
7. Monitor runs through the existing SOC console flow.
8. Export review, eval, policy, and evidence JSON.

## Verification Performed

- Parsed all Python files with `ast.parse`.
- Scanned for unresolved merge conflict markers (`<<<<<<<` / `>>>>>>>`): none found.
- Confirmed the generated product workflow Python parses.

## Verification Not Run

- Full Python unit tests were not run because this runtime does not have FastAPI/project dependencies installed.
- Frontend lint/build was not run because this runtime has `node.exe` but no `npm` or project `node_modules`.

## Deliverable

- `artifacts/ai_security_sandbox_productized_repo.zip`
