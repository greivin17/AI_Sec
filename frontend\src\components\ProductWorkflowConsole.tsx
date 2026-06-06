import { ClipboardCheck, FileDown, PlayCircle, RefreshCw, Rocket, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

interface Props {
  apiBase: string;
  getAuthHeaders: () => Promise<Record<string, string>>;
}

type OutputPanel = {
  title: string;
  body: unknown;
};

const defaultRegistration = {
  agent_id: "finance-research-agent",
  display_name: "Finance Research Agent",
  business_purpose: "Research public filings and summarize risk signals for analyst review.",
  owners: [
    {
      name: "Security Owner",
      email: "security@example.com",
      team: "AI Platform",
    },
  ],
  model: {
    provider: "azure-openai",
    model: "gpt-4.1",
    deployment: "gpt-4-1-prod",
    max_tokens_per_run: 100000,
    stores_prompts: false,
    stores_outputs: false,
  },
  tools: [
    {
      name: "file_read",
      description: "Read uploaded source documents.",
      can_read_data: true,
      can_write_data: false,
      can_call_external_network: false,
      requires_human_approval: false,
    },
    {
      name: "http_get",
      description: "Fetch approved public sources.",
      can_read_data: true,
      can_write_data: false,
      can_call_external_network: true,
      requires_human_approval: false,
    },
    {
      name: "file_write",
      description: "Write analyst reports.",
      can_read_data: false,
      can_write_data: true,
      can_call_external_network: false,
      requires_human_approval: false,
    },
  ],
  data_classes: ["internal", "confidential"],
  allowed_egress_fqdns: ["api.sec.gov"],
  prompt_injection_defenses: ["prompt_shield", "retrieved_content_scan"],
  human_approval_actions: ["http_post"],
  environment: "prod",
};

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function getAgentId(raw: string): string {
  const parsed = JSON.parse(raw) as { agent_id?: string };
  if (!parsed.agent_id) throw new Error("Registration JSON needs an agent_id.");
  return parsed.agent_id;
}

export default function ProductWorkflowConsole({ apiBase, getAuthHeaders }: Props) {
  const [registrationJson, setRegistrationJson] = useState(formatJson(defaultRegistration));
  const [selectedAgentId, setSelectedAgentId] = useState(defaultRegistration.agent_id);
  const [output, setOutput] = useState<OutputPanel>({
    title: "Workflow Ready",
    body: {
      next_step: "Register an agent to generate its first model-risk profile.",
      workflow: [
        "register",
        "risk profile",
        "red-team pack",
        "go/no-go review",
        "deployment policy",
        "evidence export",
      ],
    },
  });
  const [isBusy, setIsBusy] = useState(false);

  const decision = useMemo(() => {
    const body = output.body as { decision?: string; release_gate?: string; risk_profile?: { tier?: string } };
    return body.decision ?? body.release_gate ?? body.risk_profile?.tier ?? "pending";
  }, [output]);

  function currentAgentId(): string {
    try {
      return getAgentId(registrationJson);
    } catch {
      return selectedAgentId;
    }
  }

  async function request(path: string, options: RequestInit = {}) {
    const headers = await getAuthHeaders();
    const resp = await fetch(`${apiBase}${path}`, {
      ...options,
      headers: {
        ...headers,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers ?? {}),
      },
    });
    if (!resp.ok) {
      throw new Error(`${path} failed with HTTP ${resp.status}: ${await resp.text()}`);
    }
    return resp.json();
  }

  async function runStep(title: string, action: () => Promise<unknown>) {
    setIsBusy(true);
    try {
      const body = await action();
      setOutput({ title, body });
    } catch (err) {
      setOutput({ title: "Workflow Error", body: { error: String(err) } });
    } finally {
      setIsBusy(false);
    }
  }

  async function registerAgent() {
    await runStep("Registered Agent", async () => {
      const parsed = JSON.parse(registrationJson);
      setSelectedAgentId(parsed.agent_id);
      return request("/product/agents", {
        method: "POST",
        body: JSON.stringify(parsed),
      });
    });
  }

  async function fetchRisk() {
    const agentId = currentAgentId();
    setSelectedAgentId(agentId);
    await runStep("Risk Profile", () => request(`/product/agents/${agentId}/risk`));
  }

  async function runRedTeam() {
    const agentId = currentAgentId();
    setSelectedAgentId(agentId);
    await runStep("Red-Team Results", () =>
      request(`/product/agents/${agentId}/red-team`, { method: "POST" })
    );
  }

  async function reviewAgent() {
    const agentId = currentAgentId();
    setSelectedAgentId(agentId);
    await runStep("Go/No-Go Review", () =>
      request(`/product/agents/${agentId}/review`, { method: "POST" })
    );
  }

  async function fetchPolicy() {
    const agentId = currentAgentId();
    setSelectedAgentId(agentId);
    await runStep("Deployment Policy", () =>
      request(`/product/agents/${agentId}/deployment-policy`)
    );
  }

  async function exportEvidence() {
    const agentId = currentAgentId();
    setSelectedAgentId(agentId);
    await runStep("Evidence Export", () => request(`/product/agents/${agentId}/evidence`));
  }

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto grid max-w-7xl gap-5 xl:grid-cols-[minmax(360px,0.85fr)_1.15fr]">
        <section className="panel overflow-hidden">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-soc-blue" />
              <span className="font-semibold text-soc-text">Agent Risk Review</span>
            </div>
            <span className="badge-blue">{selectedAgentId}</span>
          </div>

          <div className="space-y-4 p-4">
            <label className="block text-xs font-medium text-soc-muted" htmlFor="agentRegistration">
              Agent declaration
            </label>
            <textarea
              id="agentRegistration"
              className="h-[440px] w-full resize-none rounded-xl border border-soc-border bg-slate-950 p-3 font-mono text-xs leading-5 text-slate-100 outline-none focus:border-blue-400"
              value={registrationJson}
              onChange={(event) => setRegistrationJson(event.target.value)}
              spellCheck={false}
            />

            <div className="grid grid-cols-2 gap-2">
              <button className="btn-primary justify-center" disabled={isBusy} onClick={registerAgent}>
                <ClipboardCheck className="h-4 w-4" />
                Register
              </button>
              <button className="btn-ghost justify-center" disabled={isBusy} onClick={fetchRisk}>
                <RefreshCw className="h-4 w-4" />
                Risk
              </button>
              <button className="btn-ghost justify-center" disabled={isBusy} onClick={runRedTeam}>
                <PlayCircle className="h-4 w-4" />
                Red-team
              </button>
              <button className="btn-ghost justify-center" disabled={isBusy} onClick={reviewAgent}>
                <ShieldCheck className="h-4 w-4" />
                Review
              </button>
              <button className="btn-ghost justify-center" disabled={isBusy} onClick={fetchPolicy}>
                <Rocket className="h-4 w-4" />
                Policy
              </button>
              <button className="btn-ghost justify-center" disabled={isBusy} onClick={exportEvidence}>
                <FileDown className="h-4 w-4" />
                Evidence
              </button>
            </div>
          </div>
        </section>

        <section className="panel min-h-[640px] overflow-hidden">
          <div className="panel-header">
            <div>
              <div className="text-sm font-semibold text-soc-text">{output.title}</div>
              <div className="text-xs text-soc-muted">Decision signal: {decision}</div>
            </div>
            <span
              className={
                decision === "go" || decision === "low"
                  ? "badge-green"
                  : decision === "no_go" || decision === "high" || decision === "critical"
                    ? "badge-red"
                    : "badge-yellow"
              }
            >
              {isBusy ? "running" : decision}
            </span>
          </div>

          <div className="grid gap-4 p-4 lg:grid-cols-3">
            <div className="insight-card">
              <div className="text-xs font-semibold uppercase tracking-wide text-soc-muted">Register</div>
              <div className="mt-2 text-sm text-soc-text">Model, tools, owners, data, egress, purpose</div>
            </div>
            <div className="insight-card">
              <div className="text-xs font-semibold uppercase tracking-wide text-soc-muted">Evaluate</div>
              <div className="mt-2 text-sm text-soc-text">OWASP, NIST, ISO mapping plus red-team pack</div>
            </div>
            <div className="insight-card">
              <div className="text-xs font-semibold uppercase tracking-wide text-soc-muted">Release</div>
              <div className="mt-2 text-sm text-soc-text">Go/no-go, OPA policy, SOC evidence export</div>
            </div>
          </div>

          <pre className="mx-4 mb-4 max-h-[520px] overflow-auto rounded-xl border border-soc-border bg-slate-950 p-4 text-xs leading-5 text-slate-100">
            {formatJson(output.body)}
          </pre>
        </section>
      </div>
    </div>
  );
}
