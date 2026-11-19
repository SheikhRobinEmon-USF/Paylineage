import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { CanonicalError, canonicalize, digest, paymentRecordDigest } from "../src/index.ts";

const dir = resolve(import.meta.dirname, "../../../policy/vectors/digest");
type Vec = { name: string; value_raw: string; expected: { canonical?: string; sha256?: string; error?: boolean } };
const vectors: Vec[] = readdirSync(dir)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Vec);

describe("cross-language digest vectors", () => {
  it("has at least 20 vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(20);
  });

  it.each(vectors.map((v) => [v.name, v] as const))("%s", async (_n, v) => {
    const value: unknown = JSON.parse(v.value_raw);
    if (v.expected.error) {
      expect(() => canonicalize(value)).toThrow(CanonicalError);
      return;
    }
    expect(canonicalize(value)).toBe(v.expected.canonical);
    expect(await digest(value)).toBe(v.expected.sha256);
  });
});

describe("payment record", () => {
  const rec = JSON.parse(
    vectors.find((v) => v.name === "payment_record")?.value_raw ?? "{}",
  ) as Record<string, unknown>;

  it("digest matches the generic digest", async () => {
    expect(await paymentRecordDigest(rec)).toBe(await digest(rec));
  });

  it("rejects extra or missing fields", async () => {
    await expect(paymentRecordDigest({ ...rec, note: "x" })).rejects.toThrow(CanonicalError);
    const { nonce: _drop, ...missing } = rec;
    await expect(paymentRecordDigest(missing)).rejects.toThrow(CanonicalError);
  });

  it("any material change changes the digest", async () => {
    const base = await paymentRecordDigest(rec);
    for (const [k, v] of [
      ["amount_minor", 1250001],
      ["beneficiary_account_id", "acct-attacker"],
      ["supplier_id", "sup-x"],
      ["currency", "EUR"],
      ["invoice_id", "inv-x"],
    ] as const) {
      expect(await paymentRecordDigest({ ...rec, [k]: v })).not.toBe(base);
    }
  });

  it("rejects non plain objects and lone surrogates", () => {
    expect(() => canonicalize(new Date())).toThrow(CanonicalError);
    expect(() => canonicalize({ s: "\ud800" })).toThrow(CanonicalError);
    expect(() => canonicalize({ n: 2 ** 53 })).toThrow(CanonicalError);
    expect(() => canonicalize(Number.NaN)).toThrow(CanonicalError);
  });
});
