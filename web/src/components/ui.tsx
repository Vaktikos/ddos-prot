import type { ReactNode } from "react";

export function Card({ title, action, children, className = "" }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-slate-800 bg-slate-900/60 ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between border-b border-slate-800 px-4 py-2.5">
          <h2 className="text-sm font-medium text-slate-300">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone = "default" }: { label: string; value: ReactNode; hint?: string; tone?: "default" | "warn" | "danger" | "ok" }) {
  const toneClass = { default: "text-slate-100", warn: "text-amber-300", danger: "text-rose-300", ok: "text-emerald-300" }[tone];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

const badgeTones: Record<string, string> = {
  online: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  synced: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  applied: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  degraded: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  pending: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  pending_approval: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  suspicious_anomaly: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  warning: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  offline: "bg-slate-500/20 text-slate-300 ring-slate-500/30",
  revoked: "bg-slate-500/20 text-slate-400 ring-slate-500/30",
  failed: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  confirmed_attack: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  open: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  traffic_spike: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  proposed: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  closed: "bg-slate-500/20 text-slate-300 ring-slate-500/30",
};

export function Badge({ value, label }: { value: string; label?: string }) {
  const tone = badgeTones[value] ?? "bg-slate-700/40 text-slate-300 ring-slate-600";
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${tone}`}>
      {label ?? value.replace(/_/g, " ")}
    </span>
  );
}

export function Button({ children, onClick, variant = "default", type = "button", disabled }: { children: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "danger"; type?: "button" | "submit"; disabled?: boolean }) {
  const styles = {
    default: "border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700",
    primary: "border-cyan-600 bg-cyan-600/20 text-cyan-200 hover:bg-cyan-600/30",
    danger: "border-rose-600 bg-rose-600/15 text-rose-200 hover:bg-rose-600/25",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`rounded-md border px-3 py-1.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-50 ${styles}`}>
      {children}
    </button>
  );
}

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>{headers.map((h) => <th key={h} className="whitespace-nowrap px-3 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">{children}</tbody>
      </table>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-6 text-center text-sm text-slate-500">{children}</div>;
}

// Sparkline draws real measured values; it never interpolates or fills gaps.
export function Sparkline({ values, height = 56, color = "#22d3ee" }: { values: (number | null | undefined)[]; height?: number; color?: string }) {
  const pts = values.map((v, i) => ({ i, v })).filter((p): p is { i: number; v: number } => typeof p.v === "number" && Number.isFinite(p.v));
  if (pts.length < 2) return <div className="flex h-14 items-center text-xs text-slate-600">zu wenige Messpunkte</div>;
  const w = 600;
  const max = Math.max(...pts.map((p) => p.v), 1e-9);
  const xs = (i: number) => (i / Math.max(values.length - 1, 1)) * w;
  const ys = (v: number) => height - (v / max) * (height - 4) - 2;
  const d = pts.map((p, k) => `${k === 0 ? "M" : "L"}${xs(p.i).toFixed(1)},${ys(p.v).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="h-14 w-full">
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
