import { useEffect, useState } from "react";
import { api, setCsrf } from "./api";
import Login from "./pages/Login";
import DashboardPage from "./pages/Dashboard";
import NodesPage from "./pages/Nodes";
import { AlertsPage, AuditPage, IncidentsPage } from "./pages/Incidents";
import type { User } from "./types";

type View = "dashboard" | "nodes" | "incidents" | "alerts" | "audit";

const views: { id: View; label: string; roles: User["role"][] }[] = [
  { id: "dashboard", label: "Übersicht", roles: ["viewer", "operator", "admin"] },
  { id: "nodes", label: "Nodes", roles: ["viewer", "operator", "admin"] },
  { id: "incidents", label: "Vorfälle", roles: ["viewer", "operator", "admin"] },
  { id: "alerts", label: "Alarme & Freigaben", roles: ["viewer", "operator", "admin"] },
  { id: "audit", label: "Audit", roles: ["admin"] },
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checked, setChecked] = useState(false);
  const [view, setView] = useState<View>("dashboard");
  const [nodeId, setNodeId] = useState<string | null>(null);

  // Restore the session after a reload; the CSRF token is re-issued by /auth/me.
  useEffect(() => {
    api<{ user: User; csrf_token: string }>("GET", "/api/v1/auth/me")
      .then((r) => { setCsrf(r.csrf_token); setUser(r.user); })
      .catch(() => setUser(null))
      .finally(() => setChecked(true));
  }, []);

  if (!checked) return null;
  if (!user) return <Login onLogin={setUser} />;

  async function logout() {
    try { await api("POST", "/api/v1/auth/logout"); } finally { setCsrf(""); setUser(null); }
  }

  const visible = views.filter((v) => v.roles.includes(user.role));
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="font-semibold tracking-tight text-slate-100">Sentinel Shield</span>
            <nav className="flex flex-wrap gap-1 text-sm">
              {visible.map((v) => (
                <button key={v.id} onClick={() => { setView(v.id); setNodeId(null); }}
                  className={`rounded px-3 py-1.5 ${view === v.id ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"}`}>
                  {v.label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span>{user.email} · {user.role}</span>
            <button onClick={logout} className="rounded border border-slate-700 px-2.5 py-1 hover:bg-slate-800">Abmelden</button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        {view === "dashboard" && <DashboardPage onOpenNode={(id) => { setNodeId(id); setView("nodes"); }} />}
        {view === "nodes" && <NodesPage user={user} nodeId={nodeId} onOpen={setNodeId} />}
        {view === "incidents" && <IncidentsPage />}
        {view === "alerts" && <AlertsPage user={user} />}
        {view === "audit" && user.role === "admin" && <AuditPage />}
      </main>
    </div>
  );
}
