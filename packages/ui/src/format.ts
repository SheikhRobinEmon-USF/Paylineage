export function money(minor: number, currency = "USD"): string {
  const sign = minor < 0 ? "-" : "";
  const abs = Math.abs(minor);
  const whole = Math.floor(abs / 100).toLocaleString("en-US");
  const cents = String(abs % 100).padStart(2, "0");
  return `${sign}${whole}.${cents} ${currency}`;
}

export function compactMoney(minor: number): string {
  const v = minor / 100;
  if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 1_000) return `$${(v / 1_000).toFixed(1)}k`;
  return `$${v.toFixed(0)}`;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

export function ago(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "";
  const s = Math.max(0, (now.getTime() - new Date(iso).getTime()) / 1000);
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 129600) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

export function chunk(hex: string, size = 8): string[] {
  const out: string[] = [];
  for (let i = 0; i < hex.length; i += size) out.push(hex.slice(i, i + size));
  return out;
}

export const STATE_LABEL: Record<string, string> = {
  proposed: "Proposed",
  evaluated: "Evaluated",
  held: "Held",
  denied: "Denied",
  awaiting_approval: "Awaiting approval",
  approved: "Approved",
  permit_issued: "Permit issued",
  executed: "Executed (simulated)",
  expired: "Expired",
};

export const FIELD_LABEL: Record<string, string> = {
  amount: "Amount",
  beneficiary_account: "Beneficiary account",
  currency: "Currency",
  invoice_number: "Invoice record",
  supplier_name: "Supplier name",
  due_date: "Due date",
  remit_email: "Remit email",
  po_number: "PO number",
};

export const SOURCE_LABEL: Record<string, string> = {
  email_body: "Email body",
  email_attachment: "Email attachment",
  portal_upload: "Portal upload",
  agent_asserted: "Agent asserted (no document)",
  supplier_master: "Supplier master",
  user_entered: "Entered by a person",
  system: "System",
};

export function humanize(code: string): string {
  return code
    .replace(/^SIGNAL_/, "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/^\w/, (c) => c.toUpperCase());
}
