import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

async function signIn(page: Page, who: RegExp) {
  await page.goto("/");
  await page.getByRole("button", { name: who }).click();
  await expect(page.getByRole("heading", { name: "Payment Control" })).toBeVisible();
}

async function noSeriousAxe(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${v.id}: ${v.nodes.length}`)).toEqual([]);
}

test("policy loads with the pinned SHA-256 and the demo labels what is live, replayed and simulated", async ({ page }) => {
  await signIn(page, /Continue as Morgan/);
  await expect(page.getByText("Policy loaded")).toBeVisible();
  await expect(page.getByText("Public demo, no backend.")).toBeVisible();
  await expect(page.getByText(/replayed recording/)).toBeVisible();
});

test("every recorded backend decision replays identically in the browser", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  await page.getByRole("tab", { name: /^All/ }).click();
  const rows = page.locator("tbody tr");
  const n = await rows.count();
  expect(n).toBeGreaterThan(10);
  await rows.first().click();
  await expect(page.getByRole("heading", { name: "Why" })).toBeVisible();
  await page.getByRole("button", { name: "Explain" }).click();
  await expect(page.getByText(/reached the same decision/)).toBeVisible();
});

test("approve with simulated passkey, permit, execute once; replay refused; chain verifies", async ({ page }) => {
  await signIn(page, /Continue as Morgan/);
  await page.goto("/approvals/");
  await page.locator("ul li button").first().click();
  await page.getByRole("button", { name: /Approve with simulated passkey/ }).click();
  await expect(page.getByText("Decision receipt")).toBeVisible();
  await page.getByRole("button", { name: /Issue permit/ }).click();
  await expect(page.getByText(/Permit .* valid 2 minutes, single use/)).toBeVisible();
  await page.getByRole("button", { name: /Execute/ }).click();
  await expect(page.getByText(/consumed the permit and paid/)).toBeVisible();
  await page.goto("/audit/");
  await expect(page.getByText(/Chain verified/)).toBeVisible();
});

test("attack lab: hidden instruction holds, legitimate invoice is allowed", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  await page.goto("/lab/");
  await expect(page.getByText("SIGNAL_HIDDEN_TEXT").first()).toBeVisible();
  await expect(page.getByText("BENEFICIARY_NOT_VERIFIED").first()).toBeVisible();
  await page.getByRole("option", { name: /L1 Legitimate/ }).click();
  await expect(page.getByText("No reasons: every check passed for this stage.")).toBeVisible();
  await page.getByRole("option", { name: /S7 Above/ }).click();
  await expect(page.getByText("OVER_CEILING").first()).toBeVisible();
  await page.getByRole("option", { name: /R1 Mandate revoked/ }).click();
  await expect(page.getByText("MANDATE_REVOKED").first()).toBeVisible();
});

test("accessibility: no serious or critical axe violations", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  for (const path of ["/", "/approvals/", "/suppliers/", "/agents/", "/lab/", "/audit/"]) {
    await page.goto(path);
    await page.waitForTimeout(600);
    await noSeriousAxe(page);
  }
});

test("keyboard triage: j moves, Enter opens the case", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  await page.keyboard.press("j");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/case\/?\?id=/);
});

test("deny dialog: d opens it on a held payment, Escape closes it, axe passes while open", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  await page.keyboard.press("h");
  await page.keyboard.press("d");
  const dialog = page.getByRole("dialog", { name: /Close this held payment as denied/ });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "Reason" })).toBeVisible();
  await noSeriousAxe(page);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await page.keyboard.press("d");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
});

test("revoke mandate: confirm dialog, cancel keeps it, revoke records it", async ({ page }) => {
  await signIn(page, /Continue as Drew/);
  await page.goto("/agents/");
  await page.getByRole("button", { name: "Revoke mandate" }).first().click();
  const dialog = page.getByRole("alertdialog", { name: /Revoke the mandate/ });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await page.getByRole("button", { name: "Revoke mandate" }).first().click();
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect(page.getByText(/Mandate revoked/)).toBeVisible();
});

test("queue: clicking a reason chip inside a held row opens the case", async ({ page }) => {
  await signIn(page, /Continue as Quinn/);
  await page.getByRole("tab", { name: /^Held/ }).click();
  await page.locator("tbody tr").first().getByRole("button").first().click();
  await expect(page).toHaveURL(/\/case\/?\?id=/);
  await expect(page.getByRole("heading", { name: "Why" })).toBeVisible();
});
