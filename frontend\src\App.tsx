import { useState } from "react";
import { ClipboardCheck, LogIn, LogOut, MessageSquare, Shield, User } from "lucide-react";
import AgentChatWorkspace from "./components/AgentChatWorkspace";
import ProductWorkflowConsole from "./components/ProductWorkflowConsole";
import { useAuthHeaders } from "./hooks/useAuthHeaders";
import { authEnabled, loginRequest } from "./authConfig";

let useIsAuthenticated: () => boolean = () => true;
let useMsal: () => {
  instance: { loginPopup: (req: unknown) => void; logout: () => void };
  accounts: { name?: string }[];
} = () => ({
  instance: { loginPopup: () => {}, logout: () => {} },
  accounts: [],
});

if (authEnabled) {
  const msalReact = await import("@azure/msal-react");
  useIsAuthenticated = msalReact.useIsAuthenticated;
  useMsal = msalReact.useMsal as typeof useMsal;
}

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
type ActiveView = "chat" | "workflow";

export default function App() {
  const [activeView, setActiveView] = useState<ActiveView>("workflow");
  const isAuthenticated = useIsAuthenticated();
  const { instance, accounts } = useMsal();
  const getAuthHeaders = useAuthHeaders();

  if (authEnabled && !isAuthenticated) {
    return (
      <div className="h-screen flex items-center justify-center bg-soc-bg px-4">
        <div className="hero-panel text-center space-y-6 max-w-xl">
          <div className="flex items-center justify-center gap-3">
            <Shield className="w-8 h-8 text-soc-blue" />
            <h1 className="text-2xl font-bold text-soc-text">Secure Agent Chat</h1>
          </div>
          <p className="text-soc-muted text-sm leading-6">
            Sign in to chat with governed agents and upload files. Investigation and alerting are performed in Azure.
          </p>
          <button
            onClick={() => instance.loginPopup(loginRequest)}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-soc-blue text-white font-medium hover:bg-blue-600 transition-colors"
          >
            <LogIn className="w-4 h-4" />
            Sign in with Microsoft
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell h-screen flex flex-col bg-soc-bg overflow-hidden">
      <header className="shrink-0 border-b border-soc-border bg-soc-panel/85 backdrop-blur-xl">
        <div className="flex min-h-14 items-center px-4 gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-soc-blue" />
            <span className="font-bold text-soc-text text-sm tracking-tight md:text-base">
              AI Security Sandbox
            </span>
            <span className="badge badge-blue text-xs hidden sm:inline-flex">Azure-first Demo</span>
          </div>

          <div className="flex items-center gap-1 rounded-xl border border-soc-border bg-white p-1">
            <button
              className={`btn px-2 py-1 text-xs ${
                activeView === "workflow" ? "bg-blue-50 text-blue-700" : "text-soc-muted"
              }`}
              onClick={() => setActiveView("workflow")}
            >
              <ClipboardCheck className="h-3.5 w-3.5" />
              Review
            </button>
            <button
              className={`btn px-2 py-1 text-xs ${
                activeView === "chat" ? "bg-blue-50 text-blue-700" : "text-soc-muted"
              }`}
              onClick={() => setActiveView("chat")}
            >
              <MessageSquare className="h-3.5 w-3.5" />
              Chat
            </button>
          </div>

          <div className="ml-auto flex items-center gap-3 text-xs text-soc-muted">
            <span className="hidden md:inline">
              Review, deploy, monitor, and audit governed AI agents.
            </span>

            {authEnabled && accounts.length > 0 && (
              <div className="flex items-center gap-2 ml-2 pl-2 border-l border-soc-border">
                <User className="w-3.5 h-3.5" />
                <span className="hidden lg:inline truncate max-w-[120px]">
                  {accounts[0].name ?? "User"}
                </span>
                <button
                  onClick={() => instance.logout()}
                  className="p-1 rounded hover:bg-soc-accent transition-colors"
                  title="Sign out"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1 overflow-hidden">
        {activeView === "workflow" ? (
          <ProductWorkflowConsole apiBase={API_BASE} getAuthHeaders={getAuthHeaders} />
        ) : (
          <AgentChatWorkspace apiBase={API_BASE} getAuthHeaders={getAuthHeaders} />
        )}
      </main>
    </div>
  );
}
