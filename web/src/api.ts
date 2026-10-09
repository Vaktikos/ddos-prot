// Thin client for the panel API. The CSRF token lives in memory only; the session
// itself is an HttpOnly cookie that scripts cannot read.

let csrfToken = "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function setCsrf(token: string) {
  csrfToken = token;
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(res.status, (data && data.error) || `HTTP ${res.status}`);
  }
  return data as T;
}

export const fmt = {
  num(v: number | null | undefined, digits = 0): string {
    if (v === null || v === undefined || Number.isNaN(v)) return "–";
    return v.toLocaleString("de-DE", { maximumFractionDigits: digits, minimumFractionDigits: digits });
  },
  time(v: string | null | undefined): string {
    if (!v) return "–";
    return new Date(v).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "medium" });
  },
  ago(v: string | null | undefined): string {
    if (!v) return "nie";
    const s = Math.round((Date.now() - new Date(v).getTime()) / 1000);
    if (s < 60) return `vor ${s} s`;
    if (s < 3600) return `vor ${Math.round(s / 60)} min`;
    return `vor ${Math.round(s / 3600)} h`;
  },
};
