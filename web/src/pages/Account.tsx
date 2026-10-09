import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Button, Card } from "../components/ui";
import type { User } from "../types";

// MFA setup: the secret is shown once as text and as an otpauth URI for authenticator apps.
export default function AccountPage({ user }: { user: User }) {
  const [secret, setSecret] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function start() {
    setMsg(null);
    try {
      setSecret(await api("POST", "/api/v1/auth/mfa/enroll"));
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Fehler" });
    }
  }

  async function submit(path: "enable" | "disable", e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    try {
      await api("POST", `/api/v1/auth/mfa/${path}`, { code });
      setMsg({ ok: true, text: path === "enable" ? "MFA ist aktiv. Beim nächsten Login wird der Code verlangt." : "MFA wurde deaktiviert." });
      setSecret(null);
      setCode("");
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Fehler" });
    }
  }

  return (
    <div className="max-w-xl space-y-6">
      <Card title="Konto">
        <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
          <dt className="text-slate-500">E-Mail</dt><dd>{user.email}</dd>
          <dt className="text-slate-500">Rolle</dt><dd>{user.role}</dd>
        </dl>
      </Card>

      <Card title="Zwei-Faktor-Anmeldung (TOTP)">
        {msg && <div className={`mb-4 rounded border px-3 py-2 text-sm ${msg.ok ? "border-emerald-700/50 bg-emerald-950/30 text-emerald-300" : "border-rose-700/50 bg-rose-950/40 text-rose-300"}`}>{msg.text}</div>}
        {!secret ? (
          <div className="space-y-3 text-sm text-slate-400">
            <p>Einrichten, bestätigen Sie anschließend mit einem Code aus Ihrer Authenticator-App. Zum Deaktivieren ist ebenfalls ein gültiger Code nötig.</p>
            <div className="flex gap-2"><Button variant="primary" onClick={start}>MFA einrichten</Button></div>
            <form onSubmit={(e) => submit("disable", e)} className="flex gap-2 pt-2">
              <input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="Code zum Deaktivieren" value={code} onChange={(e) => setCode(e.target.value)} />
              <Button type="submit" variant="danger">MFA deaktivieren</Button>
            </form>
          </div>
        ) : (
          <form onSubmit={(e) => submit("enable", e)} className="space-y-3 text-sm">
            <p className="text-slate-400">Geheimnis in die Authenticator-App eintragen (wird nur jetzt angezeigt):</p>
            <code className="block break-all rounded bg-slate-950 p-2 font-mono text-xs text-amber-200">{secret.secret}</code>
            <a className="text-xs text-cyan-400 underline" href={secret.otpauth_uri}>otpauth-Link öffnen</a>
            <input required inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="6-stelliger Code" value={code} onChange={(e) => setCode(e.target.value)} />
            <Button type="submit" variant="primary">Bestätigen und aktivieren</Button>
          </form>
        )}
      </Card>
    </div>
  );
}
