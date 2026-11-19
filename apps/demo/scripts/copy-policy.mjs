// Copy the exact policy.wasm into the static site and refuse to build on a hash mismatch.
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const wasm = readFileSync(join(root, "policy/dist/policy.wasm"));
const sha = createHash("sha256").update(wasm).digest("hex");
const pinned = readFileSync(join(root, "policy/dist/policy.sha256"), "utf8").split(/\s+/)[0];
const fixture = JSON.parse(readFileSync(join(here, "../src/fixtures/demo.json"), "utf8")).policy_sha256;
if (sha !== pinned || sha !== fixture) {
  console.error(`policy hash mismatch: wasm ${sha} pinned ${pinned} fixtures ${fixture}. Rebuild policy and re-export fixtures.`);
  process.exit(1);
}
mkdirSync(join(here, "../public/policy"), { recursive: true });
copyFileSync(join(root, "policy/dist/policy.wasm"), join(here, "../public/policy/policy.wasm"));
console.log(`copied policy.wasm ${sha.slice(0, 12)}`);
