import { useEffect, useState } from "react";
import { api, fmt } from "../api";
import { Badge, Card, Empty, Sparkline, Stat, Table } from "../components/ui";
import type { Dashboard, Node, SeriesPoint } from "../types";

export default function DashboardPage({ onOpenNode }: { onOpenNode: (id: string) => void }) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [nodeId, setNodeId] = useState<string>("");
  const [range, setRange] = useState("1h");
  const [nodes, setNodes] = useState<Node[]>([]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const d = await api<Dashboard>("GET", "/api/v1/dashboard");
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : "Fehler");
      }
    };
    load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    api<Node[]>("GET", "/api/v1/nodes").then((n) => {
      setNodes(n);
      if (!nodeId && n.length) setNodeId(n[0].id);
    }).catch(() => undefined);
  }, [nodeId]);

  useEffect(() => {
    if (!nodeId) return;
    api<SeriesPoint[]>("GET", `/api/v1/nodes/${nodeId}/metrics?range=${range}`).then(setSeries).catch(() => setSeries([]));
  }, [nodeId, range]);

  if (error && !data) return <Card title="Dashboard"><div className="text-rose-300">{error}</div></Card>;
  if (!data) return <div className="text-sm text-slate-500">Lade Dashboard …</div>;

  const online = data.nodes["online"] ?? 0;
  const total = Object.values(data.nodes).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      <div className="text-xs text-slate-500">Stand {fmt.time(data.generated_at)} · Werte aus Messungen der letzten 2 Minuten, ältere Werte werden nicht angezeigt</div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-5">
        <Stat label="Geschützte Ziele" value={fmt.num(data.protected_targets)} />
        <Stat label="Nodes online" value={`${online} / ${total}`} tone={online < total ? "warn" : "ok"} />
        <Stat label="Durchsatz" value={`${fmt.num(data.throughput_gbps, 3)} Gbit/s`} />
        <Stat label="Pakete" value={`${fmt.num(data.pps)} pps`} />
        <Stat label="Verworfen (Mitigation)" value={`${fmt.num(data.dropped_pps)} pps`} tone={data.dropped_pps > 0 ? "warn" : "default"} />
        <Stat label="Offene Vorfälle" value={fmt.num(data.open_incidents)} hint={`davon bestätigt: ${data.confirmed_open}`} tone={data.confirmed_open > 0 ? "danger" : "default"} />
        <Stat label="Vorfälle 24 h" value={fmt.num(data.incidents_24h)} />
        <Stat label="Aktive Maßnahmen" value={fmt.num(data.active_mitigations)} />
        <Stat label="Wartet auf Freigabe" value={fmt.num(data.pending_approvals)} tone={data.pending_approvals > 0 ? "warn" : "default"} />
        <Stat label="Aktive Sperren" value={fmt.num(data.active_blocks)} hint={`offene Alarme: ${data.unacked_alerts}`} />
      </div>

      <Card title="Verlauf" action={
        <div className="flex items-center gap-2 text-xs">
          <select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
            {nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
          </select>
          <select value={range} onChange={(e) => setRange(e.target.value)}>
            {["1h", "6h", "24h", "7d"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>}>
        <div className="grid gap-6 md:grid-cols-3">
          <div>
            <div className="mb-1 text-xs text-slate-500">Durchsatz (Gbit/s)</div>
            <Sparkline values={series.map((p) => p.gbps)} />
          </div>
          <div>
            <div className="mb-1 text-xs text-slate-500">Pakete pro Sekunde</div>
            <Sparkline values={series.map((p) => p.pps)} color="#a78bfa" />
          </div>
          <div>
            <div className="mb-1 text-xs text-slate-500">CPU (%)</div>
            <Sparkline values={series.map((p) => p.cpu_percent)} color="#34d399" />
          </div>
        </div>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Nodes">
          {data.node_details.length === 0 ? <Empty>Noch keine Nodes registriert.</Empty> : (
            <Table headers={["Node", "Status", "CPU", "RAM", "Gbit/s", "pps", "Policy", "Messung"]}>
              {data.node_details.map((n) => (
                <tr key={n.id} className="cursor-pointer hover:bg-slate-800/40" onClick={() => onOpenNode(n.id)}>
                  <td className="px-3 py-2 font-medium text-slate-100">{n.name}</td>
                  <td className="px-3 py-2"><Badge value={n.status} /></td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(n.cpu_percent, 1)} %</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(n.mem_percent, 1)} %</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(n.gbps, 3)}</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(n.pps)}</td>
                  <td className="px-3 py-2"><Badge value={n.sync_status} label={`v${n.applied_policy_version}/${n.desired_policy_version}`} /></td>
                  <td className="px-3 py-2 text-xs text-slate-500">{n.sampled_at ? fmt.ago(n.sampled_at) : "keine aktuelle Messung"}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>

        <Card title="Geschützte Ziele">
          {data.target_details.length === 0 ? <Empty>Noch keine Ziele definiert.</Empty> : (
            <Table headers={["Ziel", "Node", "Gbit/s", "pps", "SYN/s", "Verworfen/s"]}>
              {data.target_details.map((t) => (
                <tr key={t.id}>
                  <td className="px-3 py-2"><div className="font-medium text-slate-100">{t.name}</div><div className="font-mono text-xs text-slate-500">{t.prefix}</div></td>
                  <td className="px-3 py-2 text-slate-400">{t.node_name}</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(t.gbps, 3)}</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(t.pps)}</td>
                  <td className="px-3 py-2 tabular-nums">{fmt.num(t.syn_pps)}</td>
                  <td className={`px-3 py-2 tabular-nums ${(t.dropped_pps ?? 0) > 0 ? "text-amber-300" : ""}`}>{fmt.num(t.dropped_pps)}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
      {online === 0 && total > 0 && <div className="text-sm text-amber-300">Kein Node sendet aktuell Messwerte. Lokaler Schutz läuft unabhängig vom Panel weiter.</div>}
    </div>
  );
}
