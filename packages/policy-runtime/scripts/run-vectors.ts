/**
 * Node half of `make parity`. Runs every decision vector through the TS
 * runtime and prints one JSON line per vector: {name, decision, reasons}.
 * Usage: node packages/policy-runtime/scripts/run-vectors.ts [policyDir]
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createPolicyRuntime, strictParse } from "../src/index.ts";

const policyDir = resolve(process.argv[2] ?? "policy");
const read = (p: string): unknown => JSON.parse(readFileSync(join(policyDir, p), "utf8"));

const runtime = await createPolicyRuntime({
  wasm: readFileSync(join(policyDir, "dist/policy.wasm")),
  expectedSha256: readFileSync(join(policyDir, "dist/policy.sha256"), "utf8").trim().split(/\s+/)[0] ?? "",
  inputSchema: read("schema/input.v1.json") as object,
  outputSchema: read("schema/output.v1.json") as object,
  reasonCodes: read("schema/reason_codes.v1.json") as never,
});
if (runtime.loadError) {
  console.error(`policy runtime unavailable: ${runtime.loadError}`);
}

const dir = join(policyDir, "vectors/decision");
for (const file of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
  const vec = JSON.parse(readFileSync(join(dir, file), "utf8")) as { name: string; input?: unknown; input_raw?: string };
  let input: unknown = vec.input;
  let parseFailed = false;
  if (vec.input_raw !== undefined) {
    try {
      input = strictParse(vec.input_raw);
    } catch {
      parseFailed = true;
    }
  }
  const d = parseFailed
    ? { decision: "deny", reasons: ["INPUT_INVALID"] }
    : runtime.evaluate(input);
  console.log(JSON.stringify({ name: vec.name, decision: d.decision, reasons: d.reasons }));
}
