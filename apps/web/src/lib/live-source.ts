import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { ApiError, type AuditView, type DataSource } from "@paylineage/ui";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let body: { detail?: { code?: string; message?: string; detail?: unknown } | string } = {};
    try {
      body = await res.json();
    } catch {
      /* not json */
    }
    const d = typeof body.detail === "object" ? body.detail : { message: String(body.detail ?? res.statusText) };
    throw new ApiError(res.status, d.code ?? `HTTP_${res.status}`, d.message ?? res.statusText, d.detail);
  }
  return (await res.json()) as T;
}

const post = <T,>(path: string, body?: unknown) => call<T>(path, body === undefined ? { method: "POST" } : { method: "POST", body: JSON.stringify(body) });

/** DataSource over the real API. The browser holds no authority; every call is re-derived server side. */
export const liveSource: DataSource = {
  mode: "live",
  me: async () => {
    try {
      return await call("/v1/me");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return null;
      throw e;
    }
  },
  personas: () => call("/v1/auth/personas"),
  signInAs: async (handle) => {
    await post("/v1/auth/dev-login", { handle });
    return call("/v1/me");
  },
  signOut: async () => {
    await post("/v1/auth/logout");
  },
  policy: () => call("/v1/policy"),
  policyWasm: async () => {
    const res = await fetch("/v1/policy/policy.wasm");
    return { bytes: new Uint8Array(await res.arrayBuffer()), sha256: res.headers.get("x-policy-sha256") ?? "" };
  },
  queue: () => call("/v1/queue"),
  payment: (id) => call(`/v1/payments/${encodeURIComponent(id)}`),
  explain: (id) => post(`/v1/payments/${encodeURIComponent(id)}/explain`),
  clearHold: (id, code, note) => post(`/v1/payments/${encodeURIComponent(id)}/clear-hold`, { code, note }),
  recheck: (id) => post(`/v1/payments/${encodeURIComponent(id)}/recheck`),
  deny: (id, reason) => post(`/v1/payments/${encodeURIComponent(id)}/deny`, { reason }),
  edit: (id, change) => post(`/v1/payments/${encodeURIComponent(id)}/edit`, change),
  beginApproval: (id) => post(`/v1/payments/${encodeURIComponent(id)}/approval/begin`),
  finishApproval: (id, challenge_id, credential) => post(`/v1/payments/${encodeURIComponent(id)}/approval/finish`, { challenge_id, credential }),
  permit: (id) => post(`/v1/payments/${encodeURIComponent(id)}/permit`),
  execute: (id) => call(`/v1/payments/${encodeURIComponent(id)}/execute`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } }),
  suppliers: () => call("/v1/suppliers"),
  agents: () => call("/v1/agents"),
  revokeMandate: (agentId, reason) => post(`/v1/agents/${encodeURIComponent(agentId)}/mandates/revoke`, { reason }),
  passkey: async (options) => (await startAuthentication({ optionsJSON: options as never })) as unknown as Record<string, unknown>,
  registerPasskey: async () => {
    const b = await post<{ challenge_id: string; options: Record<string, unknown> }>("/v1/auth/passkey/register/begin");
    const cred = await startRegistration({ optionsJSON: b.options as never });
    await post("/v1/auth/passkey/register/finish", { challenge_id: b.challenge_id, credential: cred });
  },
  audit: () => call<AuditView>("/v1/audit/events"),
};
