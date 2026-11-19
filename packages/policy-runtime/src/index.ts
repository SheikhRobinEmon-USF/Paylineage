/**
 * Fail-closed wrapper around policy.wasm for browsers and Node (T0.5).
 *
 * Same semantics as backend/src/paylineage/policy/engine.py:
 *   input fails JSON Schema ............ INPUT_INVALID
 *   module hash mismatch ............... POLICY_ERROR
 *   module needs host built-ins ........ POLICY_ERROR
 *   exception during evaluation ........ POLICY_ERROR
 *   empty result set ................... POLICY_UNDEFINED
 *   malformed or inconsistent output ... POLICY_ERROR
 *
 * A browser result is display only. The backend recomputes everything (I9).
 */
import { loadPolicy, type LoadedPolicy } from "@open-policy-agent/opa-wasm";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";

export const ENTRYPOINT = "paylineage/decision";

export type Decision = "allow" | "hold" | "deny";
export type RuntimeName = "wasm-browser" | "unavailable";

export interface PolicyDecision {
  readonly decision: Decision;
  readonly reasons: readonly string[];
  readonly policyVersion: string;
  readonly policySha256: string;
  readonly runtime: RuntimeName;
  readonly detail?: string;
  /** Always "valid", never "trusted": the browser is not an authority. */
  readonly badge: "valid";
}

export interface ReasonRegistry {
  codes: Record<string, { class: "deny" | "hold"; meaning: string }>;
}

export interface PolicyArtifacts {
  wasm: Uint8Array;
  expectedSha256: string;
  inputSchema: object;
  outputSchema: object;
  reasonCodes: ReasonRegistry;
}

export interface PolicyRuntime {
  readonly sha256: string;
  readonly runtime: RuntimeName;
  readonly loadError: string | null;
  evaluate(input: unknown): PolicyDecision;
}

function failClosed(code: string, sha: string, runtime: RuntimeName, detail?: string): PolicyDecision {
  const base = { decision: "deny" as const, reasons: [code], policyVersion: "unknown", policySha256: sha, runtime, badge: "valid" as const };
  return detail === undefined ? base : { ...base, detail };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Read the module's required host built-ins via its own ABI exports. */
function requiredBuiltins(policy: LoadedPolicy): Record<string, number> {
  const instance = policy.wasmInstance as unknown as WebAssembly.Instance;
  const exportsObj = instance.exports as Record<string, unknown>;
  const builtins = exportsObj["builtins"];
  const dump = exportsObj["opa_json_dump"];
  if (typeof builtins !== "function" || typeof dump !== "function") {
    throw new Error("module lacks ABI exports");
  }
  const strAddr = (dump as (a: number) => number)((builtins as () => number)());
  const mem = new Uint8Array(policy.mem.buffer);
  let end = strAddr;
  while (end < mem.length && mem[end] !== 0) end++;
  const parsed: unknown = JSON.parse(new TextDecoder().decode(mem.subarray(strAddr, end)));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("builtins() did not return an object");
  }
  return parsed as Record<string, number>;
}

class UnavailableRuntime implements PolicyRuntime {
  readonly runtime = "unavailable" as const;
  readonly sha256: string;
  readonly loadError: string;
  constructor(sha256: string, loadError: string) {
    this.sha256 = sha256;
    this.loadError = loadError;
  }
  evaluate(): PolicyDecision {
    return failClosed("POLICY_ERROR", this.sha256, this.runtime, this.loadError);
  }
}

class WasmRuntime implements PolicyRuntime {
  readonly runtime = "wasm-browser" as const;
  readonly loadError = null;
  readonly sha256: string;
  private readonly policy: LoadedPolicy;
  private readonly validateInput: ValidateFunction;
  private readonly validateOutput: ValidateFunction;
  private readonly registry: ReasonRegistry;
  constructor(
    sha256: string,
    policy: LoadedPolicy,
    validateInput: ValidateFunction,
    validateOutput: ValidateFunction,
    registry: ReasonRegistry,
  ) {
    this.sha256 = sha256;
    this.policy = policy;
    this.validateInput = validateInput;
    this.validateOutput = validateOutput;
    this.registry = registry;
  }

  evaluate(input: unknown): PolicyDecision {
    if (!this.validateInput(input)) {
      const msg = this.validateInput.errors?.[0]?.message ?? "invalid";
      return failClosed("INPUT_INVALID", this.sha256, this.runtime, msg);
    }
    let raw: unknown;
    try {
      const results: unknown = this.policy.evaluate(input, ENTRYPOINT);
      if (!Array.isArray(results) || results.length !== 1) {
        return failClosed("POLICY_UNDEFINED", this.sha256, this.runtime, "empty result set");
      }
      const first: unknown = results[0];
      if (typeof first !== "object" || first === null || !("result" in first)) {
        return failClosed("POLICY_UNDEFINED", this.sha256, this.runtime, "no result");
      }
      raw = (first as { result: unknown }).result;
    } catch (err) {
      return failClosed("POLICY_ERROR", this.sha256, this.runtime, err instanceof Error ? err.message : "error");
    }
    try {
      return this.checkOutput(raw);
    } catch (err) {
      return failClosed("POLICY_ERROR", this.sha256, this.runtime, err instanceof Error ? err.message : "error");
    }
  }

  private checkOutput(raw: unknown): PolicyDecision {
    if (!this.validateOutput(raw)) throw new Error("output schema");
    const out = raw as { decision: Decision; reasons: string[]; policy_version: string };
    const reasons = out.reasons;
    const sorted = [...new Set(reasons)].sort();
    if (sorted.length !== reasons.length || sorted.some((r, i) => r !== reasons[i])) {
      throw new Error("reasons not sorted and unique");
    }
    const classes = new Set<string>();
    for (const r of reasons) {
      const meta = this.registry.codes[r];
      if (meta === undefined) throw new Error(`unknown reason ${r}`);
      classes.add(meta.class);
    }
    if (out.decision === "allow" && reasons.length > 0) throw new Error("allow with reasons");
    if (out.decision === "hold" && !(classes.size === 1 && classes.has("hold"))) throw new Error("hold codes");
    if (out.decision === "deny" && !classes.has("deny")) throw new Error("deny without deny code");
    if (out.policy_version === "unknown" && out.decision !== "deny") throw new Error("undefined version");
    return {
      decision: out.decision,
      reasons,
      policyVersion: out.policy_version,
      policySha256: this.sha256,
      runtime: this.runtime,
      badge: "valid",
    };
  }
}

/** Load and verify the policy. Never throws: failures yield an always-deny runtime. */
export async function createPolicyRuntime(artifacts: PolicyArtifacts): Promise<PolicyRuntime> {
  let sha = "";
  try {
    sha = await sha256Hex(artifacts.wasm);
    if (sha !== artifacts.expectedSha256) {
      return new UnavailableRuntime(sha, "policy.wasm hash mismatch");
    }
    const ajv = new Ajv2020({ allErrors: false, strict: true, strictRequired: false, strictTypes: false });
    const validateInput = ajv.compile(artifacts.inputSchema);
    const validateOutput = ajv.compile(artifacts.outputSchema);
    const policy = await loadPolicy(new Uint8Array(artifacts.wasm), { initial: 5, maximum: 1024 });
    const needed = requiredBuiltins(policy);
    if (Object.keys(needed).length > 0) {
      return new UnavailableRuntime(sha, `policy needs host built-ins: ${Object.keys(needed).sort().join(",")}`);
    }
    if (!(ENTRYPOINT in (policy.entrypoints as Record<string, number>))) {
      return new UnavailableRuntime(sha, "entrypoint missing");
    }
    return new WasmRuntime(sha, policy, validateInput, validateOutput, artifacts.reasonCodes);
  } catch (err) {
    return new UnavailableRuntime(sha, err instanceof Error ? err.message : "load failed");
  }
}

/** JSON.parse that matches the Python adapter: NaN and Infinity are not JSON. */
export function strictParse(text: string): unknown {
  return JSON.parse(text);
}
