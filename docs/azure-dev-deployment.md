# Azure Dev Deployment Guide

This guide configures AI Security Sandbox for a first Azure dev deployment using the existing Bicep infrastructure and GitHub Actions workflow.

## Current deployment shape

The repo already includes Azure-native infrastructure:

- Subscription-scope Bicep in `infra/main.bicep`
- Modules for networking, Key Vault, storage, monitoring, compute, APIM, approvals, App Configuration, and frontend hosting
- OIDC-based GitHub Actions deployment in `.github/workflows/deploy.yml`
- Product workflow release gate before deployment
- OPA policy sidecar/image flow
- Sentinel workbook and audit/storage wiring

## Prerequisites

Install these locally or use Azure Cloud Shell:

- Azure subscription with permission to create resource groups and assign roles
- Azure CLI
- GitHub repository admin access
- PowerShell 7 or Bash

On Windows, install Azure CLI with winget:

```powershell
winget install --id Microsoft.AzureCLI -e
```

Close and reopen PowerShell, then verify:

```powershell
az version
az login
az account show
```

If you have multiple subscriptions:

```powershell
az account set --subscription "<subscription-id>"
```

## Values to choose

For a dev deployment, start with:

```text
ENVIRONMENT=dev
LOCATION=eastus
GITHUB_ORG=greivin17
GITHUB_REPO=AI_Sec
APPROVER_EMAIL=<your-email>
```

The Bicep template also needs an Entra app registration client ID for APIM JWT validation. You can use the included registration script after Azure CLI login:

```powershell
pwsh scripts/register-app.ps1
```

Save the output `Client ID`; it becomes `AAD_CLIENT_ID`.

## Bootstrap GitHub OIDC deployment identity

From the repo root, after `az login`:

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export GITHUB_ORG="greivin17"
export GITHUB_REPO="AI_Sec"
export ENVIRONMENT="dev"
export LOCATION="eastus"

bash scripts/bootstrap.sh
```

The script creates or reuses an Entra app registration for GitHub Actions OIDC and prints the required GitHub secrets.

## GitHub secrets to configure

Set these in `Settings -> Secrets and variables -> Actions`:

```text
AZURE_CLIENT_ID=<deployment-app-client-id>
AZURE_TENANT_ID=<tenant-id>
AZURE_SUBSCRIPTION_ID=<subscription-id>
APPROVER_EMAIL=<your-email>
AAD_CLIENT_ID=<app-registration-client-id-used-by-APIM-JWT-validation>
```

Also create a GitHub Actions environment named `dev`:

`Settings -> Environments -> New environment -> dev`

Add the same environment-scoped secrets if your repository requires environment secrets for OIDC deployment.

## First deployment

After secrets are configured:

1. Open GitHub Actions.
2. Select the `Deploy` workflow.
3. Click `Run workflow`.
4. Choose `dev`.
5. Start the run.

The deployment workflow will:

- Evaluate the product workflow release gate.
- Deploy Azure infrastructure with Bicep.
- Build and push container images to ACR.
- Deploy orchestrator/frontend/OPA components.
- Configure Azure resources and emit deployment outputs.

## Local Bicep validation option

To validate the subscription-scope Bicep locally before running GitHub Actions:

```powershell
az deployment sub what-if `
  --location eastus `
  --template-file infra/main.bicep `
  --parameters environmentName=dev `
               location=eastus `
               approverEmail="<your-email>" `
               aadClientId="<aad-client-id>"
```

For an actual local deployment:

```powershell
az deployment sub create `
  --name ai-sec-dev `
  --location eastus `
  --template-file infra/main.bicep `
  --parameters environmentName=dev `
               location=eastus `
               approverEmail="<your-email>" `
               aadClientId="<aad-client-id>"
```

GitHub Actions is preferred after OIDC is configured because it also handles image build and deployment.

## Post-deployment checks

After the workflow completes, capture these outputs:

- `FRONTEND_URL`
- `APIM_GATEWAY_URL`
- `ORCHESTRATOR_URL`
- `KEY_VAULT_NAME`
- `LOG_ANALYTICS_WORKSPACE_ID`
- `APP_CONFIG_ENDPOINT`

Then verify:

- Frontend loads.
- APIM gateway responds.
- Product workflow routes are reachable through the gateway.
- OPA release gate returns expected allow/deny values.
- Audit events appear in Log Analytics.
- Kill switches exist in App Configuration.

## Demo smoke test

Once deployed:

1. Register the demo agent from `docs/demo-script.md`.
2. Generate a risk profile.
3. Run the red-team/eval pack.
4. Produce a go/no-go review.
5. Fetch deployment policy bundle.
6. Export evidence.

## Known first-deploy risks

- Azure CLI is required locally unless using Cloud Shell.
- The deploy identity needs rights to create resources and role assignments.
- APIM can be slow to provision.
- Private networking and DNS can make first deployments slower to debug.
- Production deployment should not use broad contributor permissions long term.
- Validate Azure costs before leaving dev resources running.

## Recommended path

1. Install Azure CLI and run `az login`.
2. Run `scripts/register-app.ps1` to create the APIM/frontend app registration.
3. Run `scripts/bootstrap.sh` to create GitHub Actions OIDC deployment identity.
4. Add the printed secrets to GitHub.
5. Run the `Deploy` workflow for `dev`.
6. Run the demo smoke test.
7. Only then plan production hardening.