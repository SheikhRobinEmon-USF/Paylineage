/**
 * RFC 8785 canonical JSON and SHA-256 digests (T0.7).
 *
 * Mirrors backend/src/paylineage/canonical. Both reject the same inputs:
 * integers outside the safe range, non-finite numbers, lone surrogates and
 * anything that is not plain JSON. Shared vectors: policy/vectors/digest/.
 */
import canonicalizeLib from "canonicalize";

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
export const PAYMENT_RECORD_SCHEMA = "paylineage.payment.v1";

export class CanonicalError extends Error {
  override name = "CanonicalError";
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function check(value: unknown, path: string): asserts value is JsonValue {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new CanonicalError(`${path}: non-finite number`);
    // I-JSON (RFC 7493) profile: any integral value must be a safe integer.
    // JS cannot tell 1e30 from a 31 digit integer, so the rule is by value.
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalError(`${path}: integral value outside safe range`);
    }
    return;
  }
  if (typeof value === "string") {
    if (!value.isWellFormed()) throw new CanonicalError(`${path}: string is not well formed Unicode`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => check(v, `${path}[${i}]`));
    return;
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalError(`${path}: not a plain object`);
    }
    for (const [k, v] of Object.entries(value)) {
      if (!k.isWellFormed()) throw new CanonicalError(`${path}.<key>: key is not well formed Unicode`);
      check(v, `${path}.${k}`);
    }
    return;
  }
  throw new CanonicalError(`${path}: unsupported type ${typeof value}`);
}

export function canonicalize(value: unknown): string {
  check(value, "$");
  const out = canonicalizeLib(value);
  if (typeof out !== "string") throw new CanonicalError("value is not serializable");
  return out;
}

const encoder = new TextEncoder();

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value));
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const copy = new Uint8Array(data);
  return toHex(await globalThis.crypto.subtle.digest("SHA-256", copy));
}

export async function digest(value: unknown): Promise<string> {
  return sha256Hex(canonicalBytes(value));
}

export const PAYMENT_RECORD_FIELDS = [
  "schema",
  "payment_id",
  "version",
  "amount_minor",
  "currency",
  "supplier_id",
  "beneficiary_account_id",
  "invoice_id",
  "invoice_digest",
  "agent_id",
  "mandate_version",
  "policy_version",
  "policy_sha256",
  "operation",
  "nonce",
  "expires_at_ms",
] as const;

export type PaymentRecord = {
  schema: typeof PAYMENT_RECORD_SCHEMA;
  payment_id: string;
  version: number;
  amount_minor: number;
  currency: string;
  supplier_id: string;
  beneficiary_account_id: string;
  invoice_id: string;
  invoice_digest: string;
  agent_id: string;
  mandate_version: number;
  policy_version: string;
  policy_sha256: string;
  operation: "pay_invoice";
  nonce: string;
  expires_at_ms: number;
};

export async function paymentRecordDigest(record: Record<string, unknown>): Promise<string> {
  const keys = Object.keys(record).sort();
  const expected = [...PAYMENT_RECORD_FIELDS].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    throw new CanonicalError("record fields differ from the canonical payment record");
  }
  if (record["schema"] !== PAYMENT_RECORD_SCHEMA) throw new CanonicalError("wrong record schema tag");
  return digest(record);
}
