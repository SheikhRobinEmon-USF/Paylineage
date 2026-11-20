/**
 * In-browser engine for the public demo (no backend).
 *
 * Live in this browser: policy.wasm (same SHA-256 as the backend), RFC 8785 +
 * SHA-256 digests, the payment state machine, single use permits and an
 * IndexedDB hash chain. Replayed: the payments themselves, produced by the real
 * Python pipeline (ingestion, extraction, signals) and exported with the exact
 * policy input the backend evaluated. Simulated: passkeys (a Web Crypto key in
 * this tab), rails and supplier verification.
 */
import { PAYMENT_RECORD_SCHEMA, digest as canonicalDigest } from "@paylineage/canonical";
import { type PolicyRuntime, createPolicyRuntime, precompiledValidators } from "@paylineage/policy-runtime";
import {
  ApiError,
  type ActionResult,
  type AuditView,
  type DataSource,
  type Decision,
  type Me,
  type PaymentDetail,
  type PaymentState,
  type PolicyInfo,
  type Queue,
  type TimelineEvent,
} from "@paylineage/ui";
import reasonCodes from "../../../policy/schema/reason_codes.v1.json";
import fixtures from "./fixtures/demo.json";

type Json = Record<string, unknown>;
interface Entry {
  detail: PaymentDetail;
  input: { payment: Json & { record: Json; approvals: Json[]; permit: Json | null; mandate: Json | null; hold_clearances: Json[]; stage: string } } & Json;
  replayVerified: boolean | null;
}
interface Fixtures {
  policy_sha256: string;
  payments: { detail: PaymentDetail; input: Entry["input"] }[];
  suppliers: unknown[];
  agents: { id: string; mandates: { revoked_at: string | null }[] }[];
  personas: (Me & { handle: string })[];
}

const F = fixtures as unknown as Fixtures;
const BASE = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
const REG = reasonCodes as unknown as { codes: Record<string, { class: "deny" | "hold"; meaning: string }> };
const MEANING = (c: string) => REG.codes[c]?.meaning ?? c;
const CLEARABLE = new Set(["DUPLICATE_INVOICE", "SIGNAL_DMARC_FAIL", "SIGNAL_HIDDEN_TEXT", "SIGNAL_LOOKALIKE_DOMAIN", "SIGNAL_PROMPT_INJECTION", "SIGNAL_REPLY_TO_MISMATCH", "SIGNAL_TOOL_POISONING"]);

/** Demo clock: anchored to the fixture time so the demo never ages into MANDATE_EXPIRED. */
const ANCHOR_MS = Math.max(...F.payments.map((p) => Number(p.input["now_ms"]))) + 60_000;
const LOADED = Date.now();
const nowMs = () => ANCHOR_MS + (Date.now() - LOADED);
const iso = (ms: number) => new Date(ms).toISOString();
const clone = <T,>(x: T): T => structuredClone(x);
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// ---------------- hash chain in IndexedDB ----------------

interface ChainEvent {
  seq: number;
  kind: string;
  actor: string;
  at: string;
  subject: string;
  payload_digest: string;
  prev_hash: string;
  hash: string;
}

class Chain {
  private events: ChainEvent[] = [];
  private db: IDBDatabase | null = null;

  async open(): Promise<void> {
    try {
      this.db = await new Promise<IDBDatabase>((res, rej) => {
        const r = indexedDB.open("paylineage-demo", 1);
        r.onupgradeneeded = () => r.result.createObjectStore("events", { keyPath: "seq" });
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      const tx = this.db.transaction("events", "readwrite");
      tx.objectStore("events").clear(); // fresh chain for a fresh demo session
    } catch {
      this.db = null; // private mode or blocked storage: keep the chain in memory
    }
  }

  static async hashOf(e: Omit<ChainEvent, "hash">): Promise<string> {
    return canonicalDigest({ seq: e.seq, prev_hash: e.prev_hash, actor: e.actor, kind: e.kind, subject_id: e.subject, payload_digest: e.payload_digest, at: e.at });
  }

  async append(kind: string, actor: string, subject: string, payload: Json): Promise<void> {
    const prev = this.events.at(-1);
    const base = { seq: (prev?.seq ?? 0) + 1, kind, actor, at: iso(nowMs()), subject, payload_digest: await canonicalDigest(payload), prev_hash: prev?.hash ?? "0".repeat(64) };
    const ev = { ...base, hash: await Chain.hashOf(base) };
    this.events.push(ev);
    try {
      this.db?.transaction("events", "readwrite").objectStore("events").put(ev);
    } catch {
      /* in memory copy is authoritative for the session */
    }
  }

  async verify(): Promise<AuditView> {
    const problems: AuditView["problems"] = [];
    let prev = "0".repeat(64);
    for (const [i, e] of this.events.entries()) {
      if (e.seq !== i + 1) problems.push({ seq: e.seq, kind: "deleted", detail: "gap" });
      if (e.prev_hash !== prev) problems.push({ seq: e.seq, kind: "reordered", detail: "broken link" });
      const { hash, ...rest } = e;
      if ((await Chain.hashOf(rest)) !== hash) problems.push({ seq: e.seq, kind: "modified", detail: "hash does not recompute" });
      prev = e.hash;
    }
    return {
      events: this.events.map((e) => ({ seq: e.seq, kind: e.kind, actor: e.actor, at: e.at, hash: e.hash.slice(0, 12) })),
      verified: problems.length === 0,
      problems,
      head: prev,
      note: "Recomputed in your browser with RFC 8785 and SHA-256 (IndexedDB).",
    };
  }

  /** For the curious: tamper with one stored event and verify again. */
  tamper(): void {
    const e = this.events[Math.floor(this.events.length / 2)];
    if (e) e.actor = "attacker";
  }
}

// ---------------- engine ----------------

export class DemoEngine implements DataSource {
  readonly mode = "demo" as const;
  private rt: PolicyRuntime | null = null;
  private wasm: Uint8Array | null = null;
  private entries = new Map<string, Entry>();
  private me_: Me | null = null;
  private key: CryptoKeyPair | null = null;
  private challenges = new Map<string, { pid: string; version: number; digest: string; challenge: Uint8Array; used: boolean }>();
  private permits = new Map<string, { pid: string; digest: string; expires: number; consumed: boolean }>();
  private chain = new Chain();
  private ready: Promise<void>;

  constructor() {
    for (const p of F.payments) this.entries.set(p.detail.id, { detail: clone(p.detail), input: clone(p.input), replayVerified: null });
    try {
      const saved = sessionStorage.getItem("pl-demo-me");
      if (saved) this.me_ = JSON.parse(saved) as Me;
    } catch {
      /* ignore */
    }
    this.ready = this.boot();
  }

  private async boot(): Promise<void> {
    const res = await fetch(`${BASE}/policy/policy.wasm`);
    this.wasm = new Uint8Array(await res.arrayBuffer());
    this.rt = await createPolicyRuntime({ wasm: this.wasm, expectedSha256: F.policy_sha256, validators: precompiledValidators, reasonCodes: REG });
    await this.chain.open();
    // Replay check: the same policy.wasm in this browser must reach the backend's recorded decision.
    for (const e of this.entries.values()) {
      const d = this.rt.evaluate(e.input);
      e.replayVerified = d.decision === e.detail.decision && JSON.stringify(d.reasons) === JSON.stringify(e.detail.reasons);
      // and the canonical digest must recompute to the backend's value
      const dig = await canonicalDigest(e.detail.record);
      if (dig !== e.detail.digest) e.replayVerified = false;
      await this.chain.append("payment.replayed", "demo", e.detail.id, { decision: d.decision, reasons: [...d.reasons] });
    }
  }

  private async entry(id: string): Promise<Entry> {
    await this.ready;
    const e = this.entries.get(id);
    if (!e) throw new ApiError(404, "NOT_FOUND", "payment not found");
    return e;
  }

  private decide(e: Entry, stage: "evaluate" | "permit" | "execute"): { decision: Decision; reasons: string[] } {
    if (!this.rt) return { decision: "deny", reasons: ["POLICY_ERROR"] };
    e.input["now_ms"] = nowMs();
    e.input.payment.stage = stage;
    const d = this.rt.evaluate(e.input);
    return { decision: d.decision, reasons: [...d.reasons] };
  }

  private setState(e: Entry, state: PaymentState, d?: { decision: Decision; reasons: string[] }): void {
    e.detail.state = state;
    if (d) {
      e.detail.decision = d.decision;
      e.detail.reasons = d.reasons;
      e.detail.reason_details = d.reasons.map((code) => ({ code, meaning: MEANING(code) }));
    }
    e.detail.updated_at = iso(nowMs());
  }

  private async log(e: Entry, kind: string, payload: Json): Promise<void> {
    await this.chain.append(kind, this.me_?.name ?? "demo", e.detail.id, payload);
    const ev: TimelineEvent = { seq: e.detail.timeline.length + 1000, kind, actor: this.me_?.name ?? "demo", at: iso(nowMs()), hash: "browser", payload };
    e.detail.timeline = [...e.detail.timeline, ev];
  }

  private role(...roles: string[]): void {
    if (!this.me_ || !roles.some((r) => this.me_?.roles.includes(r))) throw new ApiError(403, "ROLE_REQUIRED", `needs one of ${roles.join(", ")}`);
  }

  // ---- DataSource ----

  async me(): Promise<Me | null> {
    return this.me_;
  }
  async personas() {
    return F.personas.map(({ handle, name, roles }) => ({ handle, name, roles }));
  }
  async signInAs(handle: string): Promise<Me> {
    const p = F.personas.find((x) => x.handle === handle);
    if (!p) throw new ApiError(404, "NOT_FOUND", "no such persona");
    this.me_ = { id: p.id, name: p.name, roles: p.roles, passkeys: 1 };
    try {
      sessionStorage.setItem("pl-demo-me", JSON.stringify(this.me_));
    } catch {
      /* ignore */
    }
    return this.me_;
  }
  async signOut(): Promise<void> {
    this.me_ = null;
  }
  async policy(): Promise<PolicyInfo> {
    await this.ready;
    return { runtime: this.rt?.runtime ?? "unavailable", sha256: F.policy_sha256, reason_codes: REG.codes, fallback_active: false };
  }
  async policyWasm() {
    await this.ready;
    return { bytes: this.wasm ?? new Uint8Array(), sha256: F.policy_sha256 };
  }
  async queue(): Promise<Queue> {
    await this.ready;
    const items = [...this.entries.values()].map((e) => {
      const { record: _r, digest: _d, fields: _f, extracted: _x, signals: _s, document: _doc, email: _em, supplier, proposed_account: _pa, decisions: _de, timeline: _t, approvals: _a, permits: _p, execution: _ex, reason_details: _rd, policy_sha256: _ps, ...rest } = e.detail;
      return { ...rest, supplier: supplier?.legal_name ?? null };
    });
    items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    return { items, exposure_minor: 0, policy_runtime: this.rt?.runtime ?? "unavailable", policy_sha256: F.policy_sha256 };
  }
  async payment(id: string): Promise<PaymentDetail> {
    const e = await this.entry(id);
    return clone({ ...e.detail, scenario: `${e.detail.scenario ?? ""}${e.replayVerified ? " (replay verified in browser)" : e.replayVerified === false ? " (REPLAY MISMATCH)" : ""}` });
  }
  async explain(id: string) {
    const e = await this.entry(id);
    const lines = [`Decision: ${e.detail.decision} (${e.detail.state}).`];
    for (const r of e.detail.reason_details) lines.push(`- ${r.code}: ${r.meaning}`);
    if (!e.detail.reasons.length) lines.push("Every check passed. It still needs a passkey approval and a fresh policy run at execution.");
    lines.push(e.replayVerified ? "This browser re-ran the exact backend policy input with the same policy.wasm and reached the same decision." : "Replay check pending.");
    return { text: lines.join("\n"), source: "template (no model runs in the public demo)", label: "Generated explanation. It is not a decision and cannot change one." };
  }
  async clearHold(id: string, code: string, note: string): Promise<ActionResult> {
    this.role("analyst", "steward");
    const e = await this.entry(id);
    if (!CLEARABLE.has(code)) throw new ApiError(409, "INPUT_INVALID", "only signal and duplicate holds can be cleared");
    e.input.payment.hold_clearances = [...e.input.payment.hold_clearances, { code, cleared_by: this.me_?.id ?? "demo", at_ms: nowMs() }];
    await this.log(e, "payment.hold_cleared", { code, note_len: note.length });
    return this.recheck(id);
  }
  async recheck(id: string): Promise<ActionResult> {
    const e = await this.entry(id);
    if (e.detail.state !== "held") throw new ApiError(409, "ILLEGAL_TRANSITION", "only held payments are rechecked");
    const d = this.decide(e, "evaluate");
    this.setState(e, d.decision === "allow" ? "awaiting_approval" : d.decision === "deny" ? "denied" : "held", d);
    await this.log(e, "payment.rechecked", d);
    return { state: e.detail.state, ...d };
  }
  async deny(id: string, reason: string): Promise<ActionResult> {
    this.role("analyst", "steward");
    const e = await this.entry(id);
    if (e.detail.state !== "held") throw new ApiError(409, "ILLEGAL_TRANSITION", "only held payments can be closed");
    this.setState(e, "denied");
    await this.log(e, "payment.denied", { reason });
    return { state: "denied" };
  }
  async edit(id: string, change: { amount_minor?: number }): Promise<ActionResult> {
    this.role("ap_specialist");
    const e = await this.entry(id);
    if (!["awaiting_approval", "approved"].includes(e.detail.state)) throw new ApiError(409, "ILLEGAL_TRANSITION", "material change only before a permit");
    const rec = e.detail.record;
    rec["version"] = Number(rec["version"]) + 1;
    if (change.amount_minor) rec["amount_minor"] = change.amount_minor;
    rec["nonce"] = crypto.randomUUID().replace(/-/g, "").slice(0, 32);
    e.detail.version = Number(rec["version"]);
    e.detail.amount_minor = Number(rec["amount_minor"]);
    e.detail.digest = await canonicalDigest(rec);
    const r = e.input.payment.record;
    r["version"] = rec["version"];
    r["amount_minor"] = rec["amount_minor"];
    r["digest"] = e.detail.digest;
    // amount is now entered by a person: provenance becomes user_entered
    const fields = e.input.payment["fields"] as Json[];
    for (const f of fields) if (f["field_name"] === "amount") Object.assign(f, { source_kind: "user_entered", trust_class: "user_entered", master_matched: false });
    e.input.payment.approvals = [];
    e.detail.approvals = [];
    const d = this.decide(e, "evaluate");
    this.setState(e, d.decision === "allow" ? "awaiting_approval" : d.decision === "deny" ? "denied" : "held", d);
    await this.log(e, "payment.material_change", { version: rec["version"], approvals_voided: true });
    return { state: e.detail.state, version: e.detail.version, ...d };
  }
  async beginApproval(id: string) {
    this.role("finance_approver");
    const e = await this.entry(id);
    if (e.detail.state !== "awaiting_approval") throw new ApiError(409, "ILLEGAL_TRANSITION", `payment is ${e.detail.state}`);
    const digest = await canonicalDigest(e.detail.record);
    const challengeId = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    const commit = await canonicalDigest({ purpose: "approve", payment_id: id, version: e.detail.version, digest, challenge_id: challengeId, nonce });
    const challenge = new Uint8Array(commit.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
    this.challenges.set(challengeId, { pid: id, version: e.detail.version, digest, challenge, used: false });
    return { challenge_id: challengeId, options: { challenge: b64u(challenge), rpId: "demo", userVerification: "required" }, record: e.detail.record, digest, supplier: e.detail.supplier, proposed_account: e.detail.proposed_account };
  }
  async passkey(options: Record<string, unknown>) {
    // SIMULATED passkey: an ECDSA P-256 key that lives in this tab.
    this.key ??= await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const data = new TextEncoder().encode(String(options["challenge"]));
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.key.privateKey, data);
    return { simulated: true, challenge: options["challenge"], signature: b64u(sig) };
  }
  async registerPasskey(): Promise<void> {
    /* the simulated key is created on first use */
  }
  async finishApproval(id: string, challengeId: string, credential: Record<string, unknown>) {
    const ch = this.challenges.get(challengeId);
    if (!ch || ch.used || ch.pid !== id) throw new ApiError(403, "CHALLENGE_INVALID", "challenge unknown or already used");
    ch.used = true;
    if (!this.key) throw new ApiError(403, "WEBAUTHN_INVALID", "no key");
    const sig = Uint8Array.from(atob(String(credential["signature"]).replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, this.key.publicKey, sig, new TextEncoder().encode(b64u(ch.challenge)));
    if (!ok || credential["challenge"] !== b64u(ch.challenge)) throw new ApiError(403, "WEBAUTHN_INVALID", "signature does not verify");
    const e = await this.entry(id);
    if ((await canonicalDigest(e.detail.record)) !== ch.digest || e.detail.version !== ch.version) throw new ApiError(409, "APPROVAL_DIGEST_MISMATCH", "record changed after the challenge");
    const approval = { approval_id: `apr-${challengeId.slice(0, 8)}`, approver_id: this.me_?.id ?? "demo", digest: ch.digest, payment_version: ch.version, expires_at_ms: nowMs() + 15 * 60_000, revoked: false, approver_active: true, approver_roles: this.me_?.roles ?? [] };
    const prior = e.input.payment.approvals;
    e.input.payment.approvals = [...prior, approval];
    const d = this.decide(e, "permit");
    if (d.decision === "deny" || (d.decision === "hold" && d.reasons.join() !== "SECOND_APPROVAL_REQUIRED")) {
      e.input.payment.approvals = prior;
      e.input.payment.stage = "evaluate";
      await this.log(e, "payment.approval_refused", d);
      throw new ApiError(403, d.reasons[0] ?? "POLICY_UNDEFINED", "approval refused", { reasons: d.reasons });
    }
    e.detail.approvals = [...e.detail.approvals, { id: approval.approval_id, approver: this.me_?.name ?? "demo", version: ch.version, digest: ch.digest, signed_at: iso(nowMs()), expires_at: iso(approval.expires_at_ms), revoked_at: null }];
    if (d.decision === "allow") this.setState(e, "approved");
    await this.log(e, "payment.approved", { digest: ch.digest, version: ch.version, simulated_passkey: true });
    return { approved: true, state: e.detail.state, receipt: { approval_id: approval.approval_id, digest: ch.digest, version: ch.version, signed_at: iso(nowMs()), expires_at: iso(approval.expires_at_ms) }, ...d };
  }
  async permit(id: string): Promise<ActionResult> {
    const e = await this.entry(id);
    if (e.detail.state !== "approved") throw new ApiError(409, "ILLEGAL_TRANSITION", `payment is ${e.detail.state}`);
    const d = this.decide(e, "permit");
    if (d.decision !== "allow") {
      await this.log(e, "permit.refused", d);
      throw new ApiError(403, d.reasons[0] ?? "POLICY_UNDEFINED", "permit refused", { reasons: d.reasons });
    }
    const pid = crypto.randomUUID();
    this.permits.set(pid, { pid: id, digest: e.detail.digest, expires: nowMs() + 120_000, consumed: false });
    e.detail.permits = [...e.detail.permits, { id: pid, digest: e.detail.digest, issued_at: iso(nowMs()), expires_at: iso(nowMs() + 120_000), consumed_at: null }];
    this.setState(e, "permit_issued");
    await this.log(e, "permit.issued", { permit_id: pid });
    return { permit_id: pid, ...d };
  }
  async execute(id: string): Promise<ActionResult> {
    const e = await this.entry(id);
    const entry = [...this.permits.entries()].find(([, p]) => p.pid === id && !p.consumed);
    if (!entry) throw new ApiError(409, "PERMIT_MISSING", "issue a permit first");
    const [permitId, permit] = entry;
    e.input.payment.permit = { permit_id: permitId, digest: permit.digest, expires_at_ms: permit.expires, consumed: permit.consumed };
    const d = this.decide(e, "execute");
    if (d.decision !== "allow" || permit.consumed) {
      await this.log(e, "execution.refused", d);
      return { executed: false, decision: { decision: d.decision, reasons: d.reasons } };
    }
    permit.consumed = true; // single use: check and consume in one synchronous step
    const ref = `SIM-${crypto.randomUUID().slice(0, 12).toUpperCase()}`;
    e.detail.execution = { bank_reference: ref, executed_at: iso(nowMs()), simulated: true };
    this.setState(e, "executed");
    await this.log(e, "payment.executed", { permit_id: permitId, bank_reference: ref, simulated: true });
    return { executed: true, bank_reference: ref, decision: { decision: d.decision, reasons: d.reasons } };
  }
  async suppliers() {
    return clone(F.suppliers) as never;
  }
  async agents() {
    return clone(F.agents) as never;
  }
  async revokeMandate(agentId: string, reason: string): Promise<ActionResult> {
    this.role("platform_engineer", "admin");
    for (const e of this.entries.values()) {
      if (e.input.payment.mandate) e.input.payment.mandate["revoked"] = true;
    }
    const a = F.agents.find((x) => x.id === agentId);
    const m = a?.mandates[0];
    if (m) m.revoked_at = iso(nowMs());
    await this.chain.append("mandate.revoked", this.me_?.name ?? "demo", agentId, { reason });
    return { revoked: true };
  }
  async audit(): Promise<AuditView> {
    await this.ready;
    return this.chain.verify();
  }
  tamperChain(): void {
    this.chain.tamper();
  }
}

export const recordSchema = PAYMENT_RECORD_SCHEMA;
/** Server render (static export) never calls the source; effects run only in the browser. */
export const ssrStub = new Proxy({ mode: "demo" } as DataSource, {
  get: (t, k) => (k in t ? t[k as keyof DataSource] : () => new Promise(() => undefined)),
});
export const hexOf = hex;
