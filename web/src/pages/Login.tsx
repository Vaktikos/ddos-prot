import { useState, type FormEvent } from "react";
import { api, setCsrf } from "../api";
import type { User } from "../types";

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ user: User; csrf_token: string }>("POST", "/api/v1/auth/login", { email, password });
      setCsrf(res.csrf_token);
      onLogin(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Anmeldung fehlgeschlagen");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-6">
        <div>
          <div className="text-lg font-semibold text-slate-100">Sentinel Shield</div>
          <div className="text-xs text-slate-500">Anmeldung am Schutz-Panel</div>
        </div>
        <label className="block text-sm">
          <span className="text-slate-400">E-Mail</span>
          <input className="mt-1 w-full" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="block text-sm">
          <span className="text-slate-400">Passwort</span>
          <input className="mt-1 w-full" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="rounded border border-rose-700/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</div>}
        <button disabled={busy} className="w-full rounded-md bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50">
          {busy ? "Anmelden …" : "Anmelden"}
        </button>
      </form>
    </div>
  );
}
