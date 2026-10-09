import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { Button, Card, Empty, Table } from "../components/ui";
import type { Profile, User } from "../types";

type Config = Profile["config"];

const generic: Config = {
  total_pps: 100000, syn_pps: 20000, udp_pps: 50000, icmp_pps: 5000, conn_pps: 0, frag_pps: 0, invalid_pps: 0, protocol_abuse_pps: 0,
  confirm_seconds: 5, clear_seconds: 30,
  mitigation: { syn_rate_per_source: 100, udp_rate_per_source: 500, auto_block_seconds: 300, drop_fragments: false, drop_invalid: false },
};

// Starting point for Minecraft Java: new connections per port are limited, and established
// traffic is not counted as an attack. Values must be tuned to the server's real player load.
const minecraft: Config = {
  total_pps: 60000, syn_pps: 400, udp_pps: 0, icmp_pps: 2000, conn_pps: 60, frag_pps: 0, invalid_pps: 0, protocol_abuse_pps: 0,
  confirm_seconds: 5, clear_seconds: 20,
  mitigation: { syn_rate_per_source: 30, udp_rate_per_source: 0, auto_block_seconds: 120, drop_fragments: false, drop_invalid: false },
};

const numberFields: { key: keyof Omit<Config, "mitigation">; label: string; hint: string }[] = [
  { key: "total_pps", label: "Gesamt pps", hint: "0 = aus" },
  { key: "syn_pps", label: "SYN/s", hint: "neue Verbindungen am Ziel" },
  { key: "udp_pps", label: "UDP/s", hint: "" },
  { key: "icmp_pps", label: "ICMP/s", hint: "" },
  { key: "conn_pps", label: "Neue Verbindungen/s je Port", hint: "z. B. Minecraft" },
  { key: "frag_pps", label: "Fragmente/s", hint: "" },
  { key: "invalid_pps", label: "Ungültige Flags/s", hint: "" },
  { key: "protocol_abuse_pps", label: "Protokollverstöße/s (Minecraft-Guard)", hint: "ungültige Handshakes, gesperrte Quellen" },
  { key: "confirm_seconds", label: "Haltezeit (s)", hint: "bis bestätigt" },
  { key: "clear_seconds", label: "Abklingzeit (s)", hint: "bis beendet" },
];

export default function ProfilesPage({ user }: { user: User }) {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("generic");
  const [cfg, setCfg] = useState<Config>(generic);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = () => api<Profile[]>("GET", "/api/v1/profiles").then(setProfiles).catch(() => setProfiles([]));
  useEffect(() => { load(); }, []);

  function preset(k: string) {
    setKind(k);
    setCfg(k === "minecraft_java" ? minecraft : generic);
  }

  async function create(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    try {
      await api("POST", "/api/v1/profiles", { name, kind, config: cfg });
      setMsg({ ok: true, text: `Profil ${name} angelegt` });
      setName("");
      load();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Fehler" });
    }
  }

  const setNum = (key: keyof Omit<Config, "mitigation">, v: string) => setCfg({ ...cfg, [key]: Number(v) });
  const setMit = (key: keyof Config["mitigation"], v: number | boolean) => setCfg({ ...cfg, mitigation: { ...cfg.mitigation, [key]: v } });

  return (
    <div className="space-y-6">
      <Card title="Schutzprofile">
        {profiles.length === 0 ? <Empty>Noch keine Profile. Ohne Profil lässt sich kein Ziel schützen.</Empty> : (
          <Table headers={["Name", "Art", "Gesamt pps", "SYN/s", "Verb./s je Port", "Haltezeit", "SYN-Limit je Quelle"]}>
            {profiles.map((p) => (
              <tr key={p.id}>
                <td className="px-3 py-2 font-medium text-slate-100">{p.name}</td>
                <td className="px-3 py-2 text-slate-400">{p.kind.replace(/_/g, " ")}</td>
                <td className="px-3 py-2 tabular-nums">{p.config.total_pps}</td>
                <td className="px-3 py-2 tabular-nums">{p.config.syn_pps}</td>
                <td className="px-3 py-2 tabular-nums">{p.config.conn_pps}</td>
                <td className="px-3 py-2 tabular-nums">{p.config.confirm_seconds} s</td>
                <td className="px-3 py-2 tabular-nums">{p.config.mitigation.syn_rate_per_source}/s</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      {user.role === "admin" && (
        <Card title="Profil anlegen" action={
          <div className="flex gap-2">
            <Button onClick={() => preset("generic")}>Vorlage Allgemein</Button>
            <Button onClick={() => preset("minecraft_java")}>Vorlage Minecraft Java</Button>
          </div>}>
          <form onSubmit={create} className="space-y-4">
            <div className="grid gap-3 md:grid-cols-3">
              <input required placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="generic">Allgemein</option>
                <option value="minecraft_java">Minecraft Java</option>
                <option value="minecraft_bedrock">Minecraft Bedrock</option>
                <option value="web">Web</option>
              </select>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {numberFields.map((f) => (
                <label key={f.key} className="text-sm">
                  <span className="text-slate-400">{f.label}</span> <span className="text-xs text-slate-600">{f.hint}</span>
                  <input className="mt-1 w-full" type="number" min={0} value={cfg[f.key]} onChange={(e) => setNum(f.key, e.target.value)} />
                </label>
              ))}
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              <label className="text-sm"><span className="text-slate-400">SYN-Limit je Quelle (/s)</span>
                <input className="mt-1 w-full" type="number" min={0} value={cfg.mitigation.syn_rate_per_source} onChange={(e) => setMit("syn_rate_per_source", Number(e.target.value))} /></label>
              <label className="text-sm"><span className="text-slate-400">UDP-Limit je Quelle (/s)</span>
                <input className="mt-1 w-full" type="number" min={0} value={cfg.mitigation.udp_rate_per_source} onChange={(e) => setMit("udp_rate_per_source", Number(e.target.value))} /></label>
              <label className="text-sm"><span className="text-slate-400">Quellsperre (s)</span>
                <input className="mt-1 w-full" type="number" min={0} max={86400} value={cfg.mitigation.auto_block_seconds} onChange={(e) => setMit("auto_block_seconds", Number(e.target.value))} /></label>
            </div>
            <div className="flex flex-wrap gap-6 text-sm text-slate-300">
              <label className="flex items-center gap-2"><input type="checkbox" checked={cfg.mitigation.drop_fragments} onChange={(e) => setMit("drop_fragments", e.target.checked)} /> Fragmente bei Vorfall verwerfen</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={cfg.mitigation.drop_invalid} onChange={(e) => setMit("drop_invalid", e.target.checked)} /> Ungültige TCP-Flags bei Vorfall verwerfen</label>
            </div>
            {msg && <div className={`rounded border px-3 py-2 text-sm ${msg.ok ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-300" : "border-rose-700/50 bg-rose-950/40 text-rose-300"}`}>{msg.text}</div>}
            <Button type="submit" variant="primary">Profil speichern</Button>
          </form>
        </Card>
      )}
    </div>
  );
}
