import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { Badge, Button, Card, Table } from "../components/ui";
import type { User } from "../types";

interface Me { mfa_enabled: boolean; recovery_codes_left: number }
interface Signing {
  backend: string; active_key_id: string; next_key_id: string; ready_to_switch: boolean;
  nodes: { id: string; name: string; status: string; trusted_key_ids: string[]; knows_next_key: boolean }[];
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

// MFA setup: the secret and the recovery codes are shown once; nothing is stored in the browser.
export default function AccountPage({ user }: { user: User }) {
  const [me, setMe] = useState<Me | null>(null);
  const [secret, setSecret] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const loadMe = () => api<Me>("GET", "/api/v1/auth/me").then(setMe).catch(() => undefined);
  useEffect(() => { loadMe(); }, []);

  async function run(fn: () => Promise<void>) {
    setMsg(null);
    try { await fn(); } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : "Fehler" }); }
  }

  const start = () => run(async () => setSecret(await api("POST", "/api/v1/auth/mfa/enroll")));

  const enable = (e: FormEvent) => { e.preventDefault(); return run(async () => {
    const res = await api<{ recovery_codes: string[] }>("POST", "/api/v1/auth/mfa/enable", { code });
    setCodes(res.recovery_codes); setSecret(null); setCode(""); loadMe();
    setMsg({ ok: true, text: "MFA ist aktiv. Speichern Sie jetzt die Recovery-Codes." });
  }); };

  const regenerate = () => run(async () => {
    const res = await api<{ recovery_codes: string[] }>("POST", "/api/v1/auth/mfa/recovery", { code });
    setCodes(res.recovery_codes); setCode(""); loadMe();
    setMsg({ ok: true, text: "Neue Codes erzeugt. Die alten sind ungültig." });
  });

  const disable = () => run(async () => {
    await api("POST", "/api/v1/auth/mfa/disable", { code });
    setCode(""); setCodes(null); loadMe();
    setMsg({ ok: true, text: "MFA wurde deaktiviert." });
  });

  return (
    <div className="max-w-3xl space-y-6">
      <Card title="Konto">
        <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
          <dt className="text-slate-500">E-Mail</dt><dd>{user.email}</dd>
          <dt className="text-slate-500">Rolle</dt><dd>{user.role}</dd>
        </dl>
      </Card>

      <Card title="Zwei-Faktor-Anmeldung (TOTP)">
        {msg && <div className={`mb-4 rounded border px-3 py-2 text-sm ${msg.ok ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-300" : "border-rose-700/50 bg-rose-950/40 text-rose-300"}`}>{msg.text}</div>}

        {codes && (
          <div className="mb-4 rounded border border-amber-600/50 bg-amber-950/30 p-3 text-sm">
            <div className="font-medium text-amber-200">Recovery-Codes (werden nur jetzt angezeigt, jeder gilt einmal)</div>
            <ul className="mt-2 grid grid-cols-2 gap-1 font-mono text-xs text-amber-100">{codes.map((c) => <li key={c}>{c}</li>)}</ul>
            <div className="mt-3 flex gap-2">
              <Button onClick={() => download("sentinel-recovery-codes.txt", codes.join("\n") + "\n")}>Als Datei speichern</Button>
              <Button onClick={() => setCodes(null)}>Ich habe sie gesichert</Button>
            </div>
          </div>
        )}

        {secret ? (
          <form onSubmit={enable} className="space-y-3 text-sm">
            <p className="text-slate-400">Geheimnis in die Authenticator-App eintragen (wird nur jetzt angezeigt):</p>
            <code className="block break-all rounded bg-slate-950 p-2 font-mono text-xs text-amber-200">{secret.secret}</code>
            <a className="text-xs text-cyan-400 underline" href={secret.otpauth_uri}>otpauth-Link öffnen</a>
            <input required inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="6-stelliger Code" value={code} onChange={(e) => setCode(e.target.value)} />
            <Button type="submit" variant="primary">Bestätigen und aktivieren</Button>
          </form>
        ) : me?.mfa_enabled ? (
          <div className="space-y-3 text-sm text-slate-400">
            <p>MFA ist aktiv. Verbleibende Recovery-Codes: <b className="text-slate-100">{me.recovery_codes_left}</b>{me.recovery_codes_left <= 2 && <span className="text-amber-300"> – bitte neue erzeugen</span>}</p>
            <div className="flex flex-wrap gap-2">
              <input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="aktueller Code" value={code} onChange={(e) => setCode(e.target.value)} />
              <Button onClick={regenerate}>Neue Recovery-Codes</Button>
              <Button variant="danger" onClick={disable}>MFA deaktivieren</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3 text-sm text-slate-400">
            <p>Schützt das Konto zusätzlich zum Passwort. Beim Einrichten erhalten Sie zehn einmalig nutzbare Recovery-Codes für den Fall, dass das Gerät verloren geht.</p>
            <Button variant="primary" onClick={start}>MFA einrichten</Button>
          </div>
        )}
      </Card>

      {user.role === "admin" && <SigningCard />}
    </div>
  );
}

function SigningCard() {
  const [s, setS] = useState<Signing | null>(null);
  useEffect(() => { api<Signing>("GET", "/api/v1/signing").then(setS).catch(() => undefined); }, []);
  if (!s) return null;
  return (
    <Card title="Signaturschlüssel des Panels">
      <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
        <dt className="text-slate-500">Backend</dt><dd>{s.backend}</dd>
        <dt className="text-slate-500">Aktiver Schlüssel</dt><dd className="font-mono text-xs">{s.active_key_id}</dd>
        <dt className="text-slate-500">Nächster Schlüssel</dt><dd className="font-mono text-xs">{s.next_key_id || "keiner angekündigt"}</dd>
      </dl>
      {s.next_key_id && (
        <div className="mt-4">
          <div className="mb-2 text-sm">{s.ready_to_switch
            ? <Badge value="online" label="alle Nodes kennen den nächsten Schlüssel: Umschalten ist sicher" />
            : <Badge value="pending" label="noch nicht alle Nodes kennen den nächsten Schlüssel: nicht umschalten" />}</div>
          <Table headers={["Node", "Status", "kennt nächsten Schlüssel"]}>
            {s.nodes.map((n) => (
              <tr key={n.id}><td className="px-3 py-2">{n.name}</td><td className="px-3 py-2"><Badge value={n.status} /></td>
                <td className="px-3 py-2">{n.knows_next_key ? "ja" : "nein"}</td></tr>
            ))}
          </Table>
        </div>
      )}
      <p className="mt-4 text-xs text-slate-500">Ablauf: neuen öffentlichen Schlüssel in PANEL_NEXT_SIGNING_PUBLIC_KEY eintragen und das Panel neu starten. Wenn alle Nodes ihn kennen, den Signer auf den neuen Schlüssel umstellen und PANEL_NEXT_SIGNING_PUBLIC_KEY entfernen. Details in docs/OPERATIONS.md.</p>
    </Card>
  );
}
