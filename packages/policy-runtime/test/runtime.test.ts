/**
 * Mirrors backend/tests/unit/test_policy_engine.py (T0.5). I8: every failure denies.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { createPolicyRuntime, type PolicyArtifacts, type PolicyRuntime } from "../src/index.ts";

const policyDir = resolve(import.meta.dirname, "../../../policy");
const read = (p: string): unknown => JSON.parse(readFileSync(join(policyDir, p), "utf8"));

function artifacts(overrides: Partial<PolicyArtifacts> = {}): PolicyArtifacts {
  return {
    wasm: readFileSync(join(policyDir, "dist/policy.wasm")),
    expectedSha256: readFileSync(join(policyDir, "dist/policy.sha256"), "utf8").split(/\s+/)[0] ?? "",
    inputSchema: read("schema/input.v1.json") as object,
    outputSchema: read("schema/output.v1.json") as object,
    reasonCodes: read("schema/reason_codes.v1.json") as PolicyArtifacts["reasonCodes"],
    ...overrides,
  };
}

const vectors = readdirSync(join(policyDir, "vectors/decision"))
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(policyDir, "vectors/decision", f), "utf8")) as {
    name: string;
    input?: unknown;
    input_raw?: string;
    expected: { decision: string; reasons: string[] };
  });

const l1 = vectors.find((v) => v.name === "L1_allow_recurring_verified");

describe("policy-runtime", () => {
  let rt: PolicyRuntime;
  beforeAll(async () => {
    rt = await createPolicyRuntime(artifacts());
  });

  it("loads the verified module", () => {
    expect(rt.loadError).toBeNull();
    expect(rt.runtime).toBe("wasm-browser");
  });

  it("allows the legitimate L1 vector and badges it valid, never trusted", () => {
    const d = rt.evaluate(l1?.input);
    expect(d.decision).toBe("allow");
    expect(d.badge).toBe("valid");
  });

  it.each(vectors.filter((v) => v.input !== undefined).map((v) => [v.name, v] as const))(
    "vector %s",
    (_name, v) => {
      const d = rt.evaluate(v.input);
      expect({ decision: d.decision, reasons: [...d.reasons] }).toEqual(v.expected);
    },
  );

  it("test_I8_hash_mismatch_denies", async () => {
    const bad = await createPolicyRuntime(artifacts({ expectedSha256: "0".repeat(64) }));
    expect(bad.loadError).toMatch(/hash mismatch/);
    expect(bad.evaluate(l1?.input).reasons).toEqual(["POLICY_ERROR"]);
  });

  it("test_I8_tampered_wasm_denies", async () => {
    const wasm = new Uint8Array(readFileSync(join(policyDir, "dist/policy.wasm")));
    wasm[wasm.length - 10] = (wasm[wasm.length - 10] ?? 0) ^ 0xff;
    const bad = await createPolicyRuntime(artifacts({ wasm }));
    expect(bad.evaluate(l1?.input).decision).toBe("deny");
  });

  it("test_I8_garbage_module_denies", async () => {
    const wasm = new TextEncoder().encode("not wasm at all");
    const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", wasm)), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    const bad = await createPolicyRuntime(artifacts({ wasm, expectedSha256: sha }));
    expect(bad.runtime).toBe("unavailable");
    expect(bad.evaluate(l1?.input).reasons).toEqual(["POLICY_ERROR"]);
  });

  it("test_I8_invalid_input_denies", () => {
    expect(rt.evaluate({ request_kind: "payment" }).reasons).toEqual(["INPUT_INVALID"]);
    expect(rt.evaluate(undefined).reasons).toEqual(["INPUT_INVALID"]);
    expect(rt.evaluate("allow").reasons).toEqual(["INPUT_INVALID"]);
  });

  const fixture = resolve(import.meta.dirname, "../../../backend/tests/fixtures/needs_builtin.wasm");
  it.skipIf(!existsSync(fixture))("test_I8_unsupported_builtin_module_denies", async () => {
    const wasm = new Uint8Array(readFileSync(fixture));
    const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", wasm)), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    const bad = await createPolicyRuntime(artifacts({ wasm, expectedSha256: sha }));
    expect(bad.loadError).toMatch(/host built-ins/);
    expect(bad.evaluate(l1?.input).decision).toBe("deny");
  });

  it("parity script prints one line per vector", () => {
    const out = execFileSync("node", [resolve(import.meta.dirname, "../scripts/run-vectors.ts"), policyDir], {
      encoding: "utf8",
    });
    expect(out.trim().split("\n")).toHaveLength(vectors.length);
    const dir = mkdtempSync(join(tmpdir(), "parity-"));
    writeFileSync(join(dir, "out.jsonl"), out);
  });
});
