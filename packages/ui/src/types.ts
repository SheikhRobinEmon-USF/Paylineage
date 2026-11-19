/** Shapes returned by the API (backend/src/paylineage/api/views.py) and by the demo engine. */

export type Decision = "allow" | "hold" | "deny";
export type PaymentState =
  | "proposed"
  | "evaluated"
  | "held"
  | "denied"
  | "awaiting_approval"
  | "approved"
  | "permit_issued"
  | "executed"
  | "expired";

export interface QueueItem {
  id: string;
  state: PaymentState;
  version: number;
  amount_minor: number;
  currency: string;
  supplier: string | null;
  supplier_id: string | null;
  invoice_number: string | null;
  decision: Decision | null;
  reasons: string[];
  exposure_minor: number;
  agent_id: string;
  created_at: string | null;
  updated_at: string | null;
  scenario: string | null;
}

export interface Queue {
  items: QueueItem[];
  exposure_minor: number;
  policy_runtime: string;
  policy_sha256: string;
}

export interface FieldFact {
  field_name: string;
  source_kind: string;
  trust_class: string;
  consistency: "consistent" | "inconsistent" | "unchecked";
  master_matched: boolean;
  note?: string;
}

export interface ExtractedView {
  field: string;
  display: string;
  source_kind: string;
  trust_class: string;
  consistency: string;
  page: number | null;
  quote: string | null;
  span_check: string | null;
  extractor: { model?: string; model_digest?: string; prompt_version?: string };
}

export interface AccountView {
  id?: string;
  masked: string;
  bank_name?: string;
  status: string;
  verified_by?: string | null;
  verified_method?: string | null;
  steward_by?: string | null;
  verified_at?: string | null;
  cooling_off_until?: string | null;
  reported_compromised_at?: string | null;
}

export interface TimelineEvent {
  seq: number;
  kind: string;
  actor: string;
  at: string | null;
  hash: string;
  payload?: Record<string, unknown>;
}

export interface DecisionRow {
  stage: string;
  decision: Decision;
  reasons: string[];
  runtime: string;
  policy_sha256: string;
  latency_us: number;
  version: number | null;
  at: string | null;
}

export interface PaymentDetail extends Omit<QueueItem, "supplier"> {
  record: Record<string, string | number>;
  digest: string;
  policy_sha256: string;
  reason_details: { code: string; meaning: string }[];
  fields: FieldFact[];
  extracted: ExtractedView[];
  signals: { code: string; severity: "low" | "medium" | "high"; detail: Record<string, unknown> }[];
  document: { filename: string | null; digest: string | null; pages: { page: number; text: string; hidden?: string }[]; trust_class: string | null };
  email: { transport: Record<string, unknown>; body: string; digest: string } | null;
  supplier: { id: string; legal_name: string; status: string; verified_domains: string[]; accounts: AccountView[] } | null;
  proposed_account: AccountView;
  decisions: DecisionRow[];
  timeline: TimelineEvent[];
  approvals: { id: string; approver: string | null; version: number; digest: string; signed_at: string | null; expires_at: string | null; revoked_at: string | null }[];
  permits: { id: string; digest: string; issued_at: string | null; expires_at: string | null; consumed_at: string | null }[];
  execution: { bank_reference: string; executed_at: string | null; simulated: boolean } | null;
}

export interface Me {
  id: string;
  name: string;
  roles: string[];
  passkeys?: number;
}

export interface Persona {
  handle: string;
  name: string;
  roles: string[];
}

export interface SupplierView {
  id: string;
  legal_name: string;
  status: string;
  verified_domains: string[];
  registry_id: string | null;
  contact_on_file: Record<string, string> | null;
  contact_recorded_at: string | null;
  accounts: AccountView[];
  requests: {
    id: string;
    kind: string;
    state: string;
    channel: string;
    requester: string | null;
    verifier: string | null;
    steward: string | null;
    risk_tier: string;
    verification: Record<string, unknown> | null;
    created_at: string | null;
    closed_at: string | null;
  }[];
  events: TimelineEvent[];
}

export interface MandateView {
  id: string;
  version: number;
  permitted_operations: string[];
  forbidden_operations: string[];
  supplier_scope: string[];
  per_proposal_ceiling_minor: number;
  daily_ceiling_minor: number;
  approver_role: string;
  second_approver_above_minor: number;
  not_before: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_by: string | null;
}

export interface AgentView {
  id: string;
  display_name: string;
  key_id: string;
  active: boolean;
  public_key_hex: string;
  mandates: MandateView[];
}

export interface PolicyInfo {
  runtime: string;
  sha256: string;
  reason_codes: Record<string, { class: "deny" | "hold"; meaning: string }>;
  fallback_active: boolean;
}

export interface ApprovalStart {
  challenge_id: string;
  options: Record<string, unknown>;
  record: Record<string, string | number>;
  digest: string;
  supplier: PaymentDetail["supplier"];
  proposed_account: AccountView;
}

export interface ApprovalResult {
  approved: boolean;
  state: PaymentState;
  receipt: { approval_id: string; digest: string; version: number; signed_at: string; expires_at: string } | null;
  decision: Decision;
  reasons: string[];
}

export interface ActionResult {
  state?: string;
  /** A plain verdict (permit, recheck) or the executor's decision object. */
  decision?: Decision | { decision: Decision; reasons: string[] };
  reasons?: string[];
  [k: string]: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: unknown;
  constructor(status: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

/** One contract, two implementations: the live API (apps/web) and the in-browser engine (apps/demo). */
export interface DataSource {
  readonly mode: "live" | "demo";
  me(): Promise<Me | null>;
  personas(): Promise<Persona[]>;
  signInAs(handle: string): Promise<Me>;
  signOut(): Promise<void>;
  policy(): Promise<PolicyInfo>;
  policyWasm(): Promise<{ bytes: Uint8Array; sha256: string }>;
  queue(): Promise<Queue>;
  payment(id: string): Promise<PaymentDetail>;
  explain(id: string): Promise<{ text: string; source: string; label: string }>;
  clearHold(id: string, code: string, note: string): Promise<ActionResult>;
  recheck(id: string): Promise<ActionResult>;
  deny(id: string, reason: string): Promise<ActionResult>;
  edit(id: string, change: { amount_minor?: number }): Promise<ActionResult>;
  beginApproval(id: string): Promise<ApprovalStart>;
  finishApproval(id: string, challengeId: string, credential: Record<string, unknown>): Promise<ApprovalResult>;
  permit(id: string): Promise<ActionResult>;
  execute(id: string): Promise<ActionResult>;
  suppliers(): Promise<SupplierView[]>;
  agents(): Promise<AgentView[]>;
  revokeMandate(agentId: string, reason: string): Promise<ActionResult>;
  /** Produce a passkey assertion for an approval challenge. Live: WebAuthn. Demo: simulated, labeled. */
  passkey(options: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Enroll a passkey for the signed in person. */
  registerPasskey(): Promise<void>;
  audit(): Promise<AuditView>;
}

export interface AuditView {
  events: TimelineEvent[];
  verified: boolean;
  problems: { seq: number; kind: string; detail: string }[];
  head: string;
  note: string;
}
