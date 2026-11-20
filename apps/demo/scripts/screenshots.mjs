// README screenshots from the static demo (make screenshots). Fictional data only.
// Needs a built demo (pnpm --filter @paylineage/demo build) and Playwright's Chromium.
import { mkdirSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const out = fileURLToPath(new URL("../../../docs/images/", import.meta.url));
const port = 3011;
const base = `http://localhost:${port}`;
mkdirSync(out, { recursive: true });

const server = spawn(process.execPath, [fileURLToPath(new URL("./serve.mjs", import.meta.url))], {
  env: { ...process.env, PORT: String(port) },
  stdio: "ignore",
});
await new Promise((r) => setTimeout(r, 600));

const browser = await chromium.launch(process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {});

async function session(theme, who = /Continue as Quinn/) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: theme });
  await ctx.addInitScript((t) => localStorage.setItem("pl-theme", t), theme);
  const page = await ctx.newPage();
  await page.goto(`${base}/`);
  await page.getByRole("button", { name: who }).click();
  await page.getByRole("heading", { name: "Payment Control" }).waitFor();
  await page.getByText("Policy loaded").waitFor();
  return { ctx, page };
}

async function shot(page, name) {
  await page.waitForTimeout(700); // charts and fonts settle
  await page.screenshot({ path: `${out}${name}.png` });
  console.log(`docs/images/${name}.png`);
}

try {
  const { ctx, page } = await session("light");
  await shot(page, "payment-control");

  await page.getByRole("tab", { name: /^Held/ }).click();
  await page.locator("tbody tr", { hasText: /hidden/i }).first().click();
  await page.getByRole("heading", { name: "Why" }).waitFor();
  await shot(page, "evidence-investigation");

  await page.goto(`${base}/suppliers/`);
  await shot(page, "supplier-master");

  await page.goto(`${base}/agents/`);
  await shot(page, "agent-authority");

  await page.goto(`${base}/lab/`);
  await page.getByText("SIGNAL_HIDDEN_TEXT").first().waitFor();
  await shot(page, "attack-lab");

  await page.goto(`${base}/audit/`);
  await page.getByText(/Chain verified/).waitFor();
  await shot(page, "audit-trail");
  await ctx.close();

  const approver = await session("light", /Continue as Morgan/);
  await approver.page.goto(`${base}/approvals/`);
  await approver.page.locator("ul li button").first().click();
  await approver.page.getByRole("button", { name: /Approve with simulated passkey/ }).waitFor();
  await shot(approver.page, "approval-center");
  await approver.ctx.close();

  const dark = await session("dark");
  await shot(dark.page, "payment-control-dark");
  await dark.ctx.close();
} finally {
  await browser.close();
  server.kill();
}
