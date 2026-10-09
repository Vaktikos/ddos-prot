import { useEffect, useState } from "react";
import { api, fmt } from "../api";
import { Badge, Button, Card, Empty, Sparkline, Table } from "../components/ui";
import type { Action, Alert, Incident, User } from "../types";

interface Detail {
  incident: Incident;
  timeline: { ts: string; action: string; payload: Partial<Incident> }[];
  target_series: { ts: string; pps: number; syn_pps: number; udp_pps: number; gbps: number }[];
  actions: { id: string; kind: string; status: string; dry_run: boolean; reason: string; rate: number; auto_block_seconds: number }[];
  classification_note: string;
}

export function IncidentsPage() {
  const [status, setStatus] = useState("all");
  const [list, setList] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<Detail | null>(null);

  useEffect(() => {
    const q = status === "all" ? "" : `?status=${status}`;
    api<Incident[]>("GET", `/api/v1/incidents${q}`).then(setList).catch(() => setList([]));
  }, [status]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    api<Detail>("GET", `/api/v1/incidents/${selected}`).then(setDetail).catch(() => setDetail(null));
  }, [selected]);

  return (
    <div className="grid gap-6 xl:grid-cols-5">
      <Card className="xl:col-span-2" title="Vorfälle" action={
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">alle</option><option value="open">offen</option><option value="closed">beendet</option>
        </select>}>
        {list.length === 0 ? <Empty>Keine Vorfälle im gewählten Filter.</Empty> : (
          <Table headers={["Start", "Ziel", "Kategorie", "Stufe", "Status"]}>
            {list.map((i) => (
              <tr key={i.id} className={`cursor-pointer hover:bg-slate-800/40 ${selected === i.id ? "bg-slate-800/60" : ""}`} onClick={() => setSelected(i.id)}>
                <td className="px-3 py-2 text-xs text-slate-400">{fmt.time(i.started_at)}</td>
                <td className="px-3 py-2 font-mono text-xs">{i.target}<div className="font-sans text-slate-500">{i.node_name}</div></td>
                <td className="px-3 py-2">{i.category.replace(/_/g, " ")}</td>
                <td className="px-3 py-2"><Badge value={i.verdict} /></td>
                <td className="px-3 py-2"><Badge value={i.status} /></td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <div className="space-y-6 xl:col-span-3">
        {!detail && <Card><Empty>Vorfall auswählen, um Verlauf, Spitzenwerte und Maßnahmen zu sehen.</Empty></Card>}
        {detail && (
          <>
            <Card title={`Vorfall auf ${detail.incident.target}`}>
              <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
                <Field label="Stufe"><Badge value={detail.incident.verdict} /></Field>
                <Field label="Konfidenz">{fmt.num(detail.incident.confidence * 100, 0)} %</Field>
                <Field label="Spitze pps">{fmt.num(detail.incident.peak_pps)}</Field>
                <Field label="Spitze Gbit/s">{fmt.num(detail.incident.peak_bps / 1e9, 3)}</Field>
                <Field label="Spitze SYN/s">{fmt.num(detail.incident.peak_syn_pps)}</Field>
                <Field label="Spitze UDP/s">{fmt.num(detail.incident.peak_udp_pps)}</Field>
                <Field label="Beginn">{fmt.time(detail.incident.started_at)}</Field>
                <Field label="Ende">{detail.incident.ended_at ? fmt.time(detail.incident.ended_at) : "läuft"}</Field>
              </div>
              <p className="mt-4 text-xs text-slate-500">{detail.classification_note}</p>
            </Card>

            <Card title="Verlauf am Ziel (gemessen)">
              <div className="space-y-3">
                <div><div className="mb-1 text-xs text-slate-500">Pakete pro Sekunde</div><Sparkline values={detail.target_series.map((p) => p.pps)} color="#f472b6" /></div>
                <div><div className="mb-1 text-xs text-slate-500">SYN pro Sekunde</div><Sparkline values={detail.target_series.map((p) => p.syn_pps)} color="#fb7185" /></div>
              </div>
            </Card>

            <Card title="Ereignisse des Agents">
              {detail.timeline.length === 0 ? <Empty>Keine Ereignisse.</Empty> : (
                <ol className="space-y-2 text-sm">
                  {detail.timeline.map((e, idx) => (
                    <li key={idx} className="flex gap-3">
                      <span className="w-40 shrink-0 text-xs text-slate-500">{fmt.time(e.ts)}</span>
                      <span className="w-24 shrink-0 text-slate-300">{e.action}</span>
                      <span className="text-slate-400">{e.payload.verdict ? <Badge value={String(e.payload.verdict)} /> : null} {fmt.num(e.payload.peak_pps)} pps</span>
                    </li>
                  ))}
                </ol>
              )}
            </Card>

            <Card title="Maßnahmen">
              {detail.actions.length === 0 ? <Empty>Keine Maßnahmen zu diesem Vorfall.</Empty> : (
                <ul className="space-y-2 text-sm">
                  {detail.actions.map((a) => (
                    <li key={a.id} className="flex flex-wrap items-center gap-2">
                      <Badge value={a.status} />
                      <span>{a.kind.replace(/_/g, " ")}</span>
                      <span className="text-slate-500">limit {a.rate}/s{a.auto_block_seconds ? `, Quellsperre ${a.auto_block_seconds} s` : ""}</span>
                      {a.dry_run && <Badge value="proposed" label="nur Vorschlag" />}
                      <span className="text-xs text-slate-500">{a.reason}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><div className="text-xs text-slate-500">{label}</div><div className="mt-0.5 tabular-nums text-slate-200">{children}</div></div>;
}

export function AlertsPage({ user }: { user: User }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const canOperate = user.role !== "viewer";

  const load = () => {
    api<Alert[]>("GET", "/api/v1/alerts").then(setAlerts).catch(() => setAlerts([]));
    api<Action[]>("GET", "/api/v1/actions").then(setActions).catch(() => setActions([]));
  };
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, []);

  async function decide(id: string, decision: "approve" | "reject") {
    setMsg(null);
    try { await api("POST", `/api/v1/actions/${id}/${decision}`); load(); }
    catch (e) { setMsg(e instanceof Error ? e.message : "Fehler"); }
  }
  async function ack(id: string) {
    try { await api("POST", `/api/v1/alerts/${id}/ack`); load(); }
    catch (e) { setMsg(e instanceof Error ? e.message : "Fehler"); }
  }

  const pending = actions.filter((a) => a.status === "pending_approval");
  return (
    <div className="space-y-6">
      {msg && <div className="rounded border border-rose-700/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{msg}</div>}
      <Card title={`Freigaben ausstehend (${pending.length})`}>
        {pending.length === 0 ? <Empty>Keine Maßnahme wartet auf Freigabe.</Empty> : (
          <Table headers={["Node", "Ziel", "Maßnahme", "Begründung", "Seit", ""]}>
            {pending.map((a) => (
              <tr key={a.id}>
                <td className="px-3 py-2">{a.node_name}</td>
                <td className="px-3 py-2 font-mono text-xs">{a.target}</td>
                <td className="px-3 py-2">{a.kind.replace(/_/g, " ")} · {a.rate}/s</td>
                <td className="px-3 py-2 text-xs text-slate-400">{a.reason}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{fmt.ago(a.created_at)}</td>
                <td className="px-3 py-2 text-right">
                  {canOperate && <div className="flex justify-end gap-2"><Button variant="primary" onClick={() => decide(a.id, "approve")}>Freigeben</Button><Button variant="danger" onClick={() => decide(a.id, "reject")}>Ablehnen</Button></div>}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <Card title="Offene Alarme">
        {alerts.length === 0 ? <Empty>Keine offenen Alarme.</Empty> : (
          <ul className="divide-y divide-slate-800">
            {alerts.map((a) => (
              <li key={a.id} className="flex flex-wrap items-start gap-3 py-3">
                <Badge value={a.severity} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-slate-100">{a.title}</div>
                  <div className="text-xs text-slate-500">{a.source} · {fmt.time(a.created_at)}</div>
                  {a.message && <div className="mt-1 break-words text-xs text-slate-400">{a.message}</div>}
                </div>
                {canOperate && <Button onClick={() => ack(a.id)}>Bestätigen</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

export function AuditPage() {
  const [rows, setRows] = useState<{ id: number; ts: string; actor_type: string; actor_id: string; action: string; target_type: string; target_id: string; details: unknown }[]>([]);
  useEffect(() => { api<typeof rows>("GET", "/api/v1/audit?limit=200").then(setRows).catch(() => setRows([])); }, []);
  return (
    <Card title="Audit-Protokoll">
      <Table headers={["Zeit", "Akteur", "Aktion", "Ziel", "Details"]}>
        {rows.map((r) => (
          <tr key={r.id}>
            <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-500">{fmt.time(r.ts)}</td>
            <td className="px-3 py-2 text-xs text-slate-400">{r.actor_type}:{r.actor_id.slice(0, 8)}</td>
            <td className="px-3 py-2 font-mono text-xs text-slate-200">{r.action}</td>
            <td className="px-3 py-2 font-mono text-xs text-slate-500">{r.target_type} {r.target_id.slice(0, 8)}</td>
            <td className="px-3 py-2 font-mono text-xs text-slate-500">{JSON.stringify(r.details).slice(0, 120)}</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
