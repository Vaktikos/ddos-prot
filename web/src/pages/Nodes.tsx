import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, fmt } from "../api";
import { Badge, Button, Card, Empty, Table } from "../components/ui";
import type { Node, PolicyVersion, Profile, Rule, Target, User } from "../types";

// The one-line installer served by this panel; the token is single use and expires in 24 hours.
function installCommand(token: string): string {
  return `curl -fsSL ${window.location.origin}/install.sh | sudo -E bash -s -- --token ${token} --management-cidr auto`;
}

export default function NodesPage({ user, nodeId, onOpen }: { user: User; nodeId: string | null; onOpen: (id: string | null) => void }) {
  if (nodeId) return <NodeDetail user={user} nodeId={nodeId} onBack={() => onOpen(null)} />;
  return <NodeList user={user} onOpen={onOpen} />;
}

function NodeList({ user, onOpen }: { user: User; onOpen: (id: string) => void }) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);
  const [form, setForm] = useState({ name: "", mode: "dry_run", cidrs: "" });

  const load = useCallback(() => api<Node[]>("GET", "/api/v1/nodes").then(setNodes).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await api<{ node: Node; enrollment_token: string }>("POST", "/api/v1/nodes", {
        name: form.name, mode: form.mode, management_cidrs: form.cidrs.split(/[\s,]+/).filter(Boolean),
      });
      setCreated({ name: res.node.name, token: res.enrollment_token });
      setForm({ name: "", mode: "dry_run", cidrs: "" });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fehler");
    }
  }

  return (
    <div className="space-y-6">
      {error && <div className="rounded border border-rose-700/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</div>}
      <Card title="Nodes">
        {nodes.length === 0 ? <Empty>Noch keine Nodes. Anlegen Sie einen Node unten und registrieren Sie den Agent mit dem Token.</Empty> : (
          <Table headers={["Name", "Standort", "Status", "Modus", "Policy", "Letzter Heartbeat", "Agent"]}>
            {nodes.map((n) => (
              <tr key={n.id} className="cursor-pointer hover:bg-slate-800/40" onClick={() => onOpen(n.id)}>
                <td className="px-3 py-2 font-medium text-slate-100">{n.name}</td>
                <td className="px-3 py-2 text-slate-400">{n.location_name ?? "–"}</td>
                <td className="px-3 py-2"><Badge value={n.status} /></td>
                <td className="px-3 py-2 text-slate-400">{n.mode.replace("_", " ")}</td>
                <td className="px-3 py-2"><Badge value={n.sync_status} label={`v${n.applied_policy_version}/${n.desired_policy_version}`} /></td>
                <td className="px-3 py-2 text-xs text-slate-500">{fmt.ago(n.last_heartbeat_at)}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{n.agent_version || "–"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      {user.role === "admin" && (
        <Card title="Node anlegen">
          <form onSubmit={create} className="grid gap-3 md:grid-cols-4">
            <input required placeholder="Name, z. B. kvm-fra-01" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
              <option value="dry_run">Dry-Run (nur beobachten)</option>
              <option value="approval">Freigabe erforderlich</option>
              <option value="auto">Automatisch (nur bestätigte Angriffe)</option>
            </select>
            <input required placeholder="Management-Netze, z. B. 203.0.113.10/32" value={form.cidrs} onChange={(e) => setForm({ ...form, cidrs: e.target.value })} />
            <Button type="submit" variant="primary">Node anlegen</Button>
          </form>
          {created && (
            <div className="mt-4 rounded border border-amber-600/50 bg-amber-950/30 p-3 text-sm">
              <div className="font-medium text-amber-200">Enrollment-Token für {created.name} (wird nur einmal angezeigt, 24 h gültig)</div>
              <code className="mt-2 block break-all font-mono text-xs text-amber-100">{created.token}</code>
              <div className="mt-3 text-xs text-amber-200">Auf dem Server als Administrator ausführen (lädt den Agent von diesem Panel, prüft die Prüfsumme, richtet alles ein und startet den Dienst):</div>
              <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-slate-300">{installCommand(created.token)}</pre>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button onClick={() => navigator.clipboard?.writeText(installCommand(created.token))}>Befehl kopieren</Button>
                <span className="text-xs text-slate-400">`--management-cidr auto` sperrt die Adresse Ihrer aktuellen SSH-Sitzung nie aus. Eine andere Adresse mit `--management-cidr 203.0.113.10/32`. Optional: `--xdp auto` für den XDP-Filter. Bei selbstsigniertem Zertifikat zusätzlich `--ca-file /pfad/panel-ca.pem`.</span>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function NodeDetail({ user, nodeId, onBack }: { user: User; nodeId: string; onBack: () => void }) {
  const [node, setNode] = useState<Node | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  // A revoked node accepts no changes; the API refuses them too.
  const canOperate = (user.role === "operator" || user.role === "admin") && node?.status !== "revoked";

  const load = useCallback(async () => {
    const [n, t, r, v, p] = await Promise.all([
      api<Node>("GET", `/api/v1/nodes/${nodeId}`),
      api<Target[]>("GET", `/api/v1/nodes/${nodeId}/targets`),
      api<Rule[]>("GET", `/api/v1/nodes/${nodeId}/rules`),
      api<PolicyVersion[]>("GET", `/api/v1/nodes/${nodeId}/policies`),
      api<Profile[]>("GET", "/api/v1/profiles"),
    ]);
    setNode(n); setTargets(t); setRules(r); setVersions(v); setProfiles(p);
  }, [nodeId]);

  useEffect(() => { load().catch((e) => setMsg({ ok: false, text: e.message })); const t = setInterval(() => load().catch(() => undefined), 10000); return () => clearInterval(t); }, [load]);

  async function run(action: () => Promise<unknown>, okText: string) {
    setMsg(null);
    try {
      await action();
      setMsg({ ok: true, text: okText });
      await load();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Fehler" });
    }
  }

  if (!node) return <div className="text-sm text-slate-500">Lade Node …</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Button onClick={onBack}>← Nodes</Button>
          <h1 className="mt-3 text-xl font-semibold text-slate-100">{node.name}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-400">
            <Badge value={node.status} /> <span>Modus: {node.mode.replace("_", " ")}</span> <span>· Host {node.hostname || "–"}</span>
            <span>· Agent {node.agent_version || "–"}</span> <span>· Heartbeat {fmt.ago(node.last_heartbeat_at)}</span>
          </div>
        </div>
      </div>

      {msg && <div className={`rounded border px-3 py-2 text-sm ${msg.ok ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-300" : "border-rose-700/50 bg-rose-950/40 text-rose-300"}`}>{msg.text}</div>}
      {node.health.errors && node.health.errors.length > 0 && (
        <div className="rounded border border-amber-700/50 bg-amber-950/30 px-3 py-2 text-sm text-amber-200">{node.health.errors.join(" · ")}</div>
      )}
      {node.guards && node.guards.length > 0 && (
        <Card title="Minecraft-Guards">
          <div className="space-y-2 text-sm">
            {node.guards.map((g) => (
              <div key={g.name} className="flex flex-wrap gap-x-4 gap-y-1 text-slate-300">
                <span className="font-medium text-slate-100">{g.name}</span>
                {!g.reachable ? <span className="text-rose-300">nicht erreichbar</span> : (
                  <>
                    <span>{g.active} aktive Verbindungen</span>
                    <span>{g.handshake_ok_ps.toFixed(1)} gültige Handshakes/s</span>
                    <span>{g.status_pings_ps.toFixed(1)} Pings/s</span>
                    <span>{g.invalid_ps.toFixed(1)} ungültig/s</span>
                    <span>{g.rate_limited_ps.toFixed(1)} begrenzt/s</span>
                    <span>{g.bans} Sperren aktiv ({g.bans_issued} gesamt)</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
      {node.sync_error && <div className="text-sm text-rose-300">Synchronisierung: {node.sync_error}</div>}

      <Card title="Betriebsmodus">
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="text-slate-400">Der Modus bestimmt, wie weit der Agent ohne Freigabe handelt.</span>
          {(["dry_run", "approval", "auto"] as const).map((m) => (
            <Button key={m} variant={node.mode === m ? "primary" : "default"} disabled={!canOperate || node.mode === m}
              onClick={() => run(() => api("POST", `/api/v1/nodes/${nodeId}/mode`, { mode: m }), `Modus auf ${m} gesetzt, neue Policy veröffentlicht`)}>
              {m === "dry_run" ? "Dry-Run" : m === "approval" ? "Mit Freigabe" : "Automatisch"}
            </Button>
          ))}
        </div>
        <div className="mt-3 text-xs text-slate-500">Management-Netze (nie sperrbar): {node.management_cidrs.join(", ")}</div>
        {user.role === "admin" && node.status !== "revoked" && node.enrolled && (
          <div className="mt-3 flex items-center gap-3 text-xs text-slate-500">
            <Button onClick={() => run(() => api("POST", `/api/v1/nodes/${nodeId}/rotate-key`), "Schlüsselrotation angefordert, der Agent tauscht beim nächsten Heartbeat")}>Node-Schlüssel rotieren</Button>
            <span>Der Agent erzeugt einen neuen Schlüssel und weist den Besitz des alten nach.</span>
          </div>
        )}
      </Card>

      <Card title="Geschützte Ziele">
        {targets.length === 0 ? <Empty>Keine Ziele. Ohne Ziele gibt es keine Erkennung.</Empty> : (
          <Table headers={["Ziel", "Profil", "Dienste", "pps", "SYN/s", "Verworfen/s", ""]}>
            {targets.map((t) => (
              <tr key={t.id}>
                <td className="px-3 py-2"><div className="text-slate-100">{t.name}</div><div className="font-mono text-xs text-slate-500">{t.prefix}</div></td>
                <td className="px-3 py-2 text-slate-400">{t.profile}</td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">{t.services.map((s) => `${s.protocol}/${s.port}`).join(", ") || "alle"}</td>
                <td className="px-3 py-2 tabular-nums">{fmt.num(t.pps)}</td>
                <td className="px-3 py-2 tabular-nums">{fmt.num(t.syn_pps)}</td>
                <td className="px-3 py-2 tabular-nums">{fmt.num(t.dropped_pps)}</td>
                <td className="px-3 py-2 text-right">{canOperate && <Button variant="danger" onClick={() => run(() => api("DELETE", `/api/v1/targets/${t.id}`), "Ziel entfernt, neue Policy veröffentlicht")}>Entfernen</Button>}</td>
              </tr>
            ))}
          </Table>
        )}
        {canOperate && <TargetForm profiles={profiles} onSubmit={(body) => run(() => api("POST", `/api/v1/nodes/${nodeId}/targets`, body), "Ziel angelegt, Policy veröffentlicht")} />}
      </Card>

      <Card title="Regeln (Allow und zeitlich begrenzte Sperren)">
        {rules.length === 0 ? <Empty>Keine aktiven Regeln.</Empty> : (
          <Table headers={["Art", "Präfix", "Begründung", "Läuft ab", ""]}>
            {rules.map((r) => (
              <tr key={r.id}>
                <td className="px-3 py-2"><Badge value={r.kind === "deny" ? "critical" : "online"} label={r.kind === "deny" ? "Sperre" : "Ausnahme"} /></td>
                <td className="px-3 py-2 font-mono text-xs">{r.prefix}</td>
                <td className="px-3 py-2 text-slate-400">{r.reason}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{r.expires_at ? fmt.time(r.expires_at) : "unbefristet"}</td>
                <td className="px-3 py-2 text-right">{canOperate && <Button variant="danger" onClick={() => run(() => api("POST", `/api/v1/rules/${r.id}/revoke`), "Regel widerrufen, neue Policy veröffentlicht")}>Widerrufen</Button>}</td>
              </tr>
            ))}
          </Table>
        )}
        {canOperate && <RuleForm onSubmit={(body) => run(() => api("POST", `/api/v1/nodes/${nodeId}/rules`, body), "Regel gespeichert, Policy veröffentlicht")} />}
      </Card>

      <Card title="Policy-Versionen">
        <Table headers={["Version", "Notiz", "Von", "Erstellt", "SHA-256", ""]}>
          {versions.map((v) => (
            <tr key={v.version}>
              <td className="px-3 py-2 tabular-nums">
                v{v.version} {v.version === node.applied_policy_version && <Badge value="applied" label="aktiv" />}
              </td>
              <td className="px-3 py-2 text-slate-400">{v.note}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{v.created_by}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{fmt.time(v.created_at)}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-600">{v.sha256.slice(0, 16)}…</td>
              <td className="px-3 py-2 text-right">
                {canOperate ? (
                  <Button onClick={() => run(() => api("POST", `/api/v1/nodes/${nodeId}/policies/${v.version}/rollback`), `Version ${v.version} als neue Version veröffentlicht`)}>Zurücksetzen</Button>
                ) : null}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}

function TargetForm({ profiles, onSubmit }: { profiles: Profile[]; onSubmit: (body: unknown) => void }) {
  const [name, setName] = useState("");
  const [prefix, setPrefix] = useState("");
  const [profile, setProfile] = useState(profiles[0]?.name ?? "");
  const [services, setServices] = useState("tcp/443");
  function submit(e: FormEvent) {
    e.preventDefault();
    const parsed = services.split(/[\s,]+/).filter(Boolean).map((s) => {
      const [protocol, port] = s.split("/");
      return { name: "", protocol, port: Number(port) };
    });
    onSubmit({ name, prefix, profile: profile || profiles[0]?.name, services: parsed });
    setName(""); setPrefix("");
  }
  return (
    <form onSubmit={submit} className="mt-4 grid gap-3 border-t border-slate-800 pt-4 md:grid-cols-5">
      <input required placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
      <input required placeholder="IP oder CIDR, z. B. 192.0.2.10" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
      <select value={profile} onChange={(e) => setProfile(e.target.value)}>
        {profiles.map((p) => <option key={p.id} value={p.name}>{p.name} ({p.kind})</option>)}
      </select>
      <input placeholder="Dienste, z. B. tcp/443 udp/53" value={services} onChange={(e) => setServices(e.target.value)} />
      <Button type="submit" variant="primary">Ziel hinzufügen</Button>
    </form>
  );
}

function RuleForm({ onSubmit }: { onSubmit: (body: unknown) => void }) {
  const [kind, setKind] = useState<"deny" | "allow">("deny");
  const [prefix, setPrefix] = useState("");
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState("24");
  function submit(e: FormEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = { kind, prefix, reason };
    if (kind === "deny") body.expires_at = new Date(Date.now() + Number(hours) * 3600_000).toISOString();
    onSubmit(body);
    setPrefix(""); setReason("");
  }
  return (
    <form onSubmit={submit} className="mt-4 grid gap-3 border-t border-slate-800 pt-4 md:grid-cols-5">
      <select value={kind} onChange={(e) => setKind(e.target.value as "deny" | "allow")}>
        <option value="deny">Sperre (befristet)</option>
        <option value="allow">Ausnahme (vertrauenswürdig)</option>
      </select>
      <input required placeholder="IP oder CIDR" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
      <input required minLength={3} placeholder="Begründung (Pflicht)" value={reason} onChange={(e) => setReason(e.target.value)} />
      <input type="number" min={1} max={720} disabled={kind === "allow"} value={hours} onChange={(e) => setHours(e.target.value)} aria-label="Laufzeit in Stunden" />
      <Button type="submit" variant="primary">Regel speichern</Button>
    </form>
  );
}
