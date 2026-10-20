import { test, expect, type Page, type Response } from "@playwright/test";

/**
 * End-to-end tests of saving and conflict handling. Each test registers its
 * own user, so they don't depend on (or change) the shared "abcd" account.
 */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

function uniqueUsername(): string {
  return `u${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

async function register(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.click("#login .pm-auth-tab:has-text('Register')");
  await page.fill("#register input[name='username']", username);
  await page.fill("#register input[name='new_pass']", PASSWORD);
  await page.fill("#register input[name='confirm_new_pass']", PASSWORD);
  await page.click("#register input[name='submit']");
  await expect(page.locator("#error-panel")).toContainText("Account created");
}

async function login(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

/** Runs `action` and waits for the vault save it triggers to succeed. */
async function saved(page: Page, action: () => Promise<void>): Promise<void> {
  const ok = page.waitForResponse(
    (r: Response) =>
      r.url().includes("/pass-table?") &&
      r.request().method() === "PUT" &&
      r.status() === 200,
  );
  await action();
  await ok;
}

async function addTable(page: Page): Promise<void> {
  await saved(page, () => page.click("button:has-text('Add Table')"));
}

async function renameTable(page: Page, index: number, name: string) {
  const nameEl = page.locator(".pm-card-name").nth(index);
  await nameEl.fill(name);
  await nameEl.press("Enter");
}

const tableNames = (page: Page) => page.locator(".pm-card-name");

test.describe("Saving from two sessions", () => {
  test("a stale session's save merges the other session's changes", async ({
    browser,
  }) => {
    const username = uniqueUsername();
    const a = await (await browser.newContext()).newPage();
    const b = await (await browser.newContext()).newPage();
    await register(a, username);
    await login(a, username);
    await login(b, username);

    await addTable(a);
    await saved(a, () => renameTable(a, 0, "From A"));

    // b still holds the version from before a's saves: its save is refused,
    // merged with a's changes and retried
    const refused = b.waitForResponse(
      (r) => r.request().method() === "PUT" && r.status() === 412,
    );
    await addTable(b);
    await refused;
    await expect(tableNames(b)).toHaveText(["From A", "New Table"]);
    await expect(b.locator(".pm-conflict")).toBeHidden();

    // and the merged vault is what was saved
    const c = await (await browser.newContext()).newPage();
    await login(c, username);
    await expect(tableNames(c)).toHaveText(["From A", "New Table"]);
  });

  test("conflicting edits pause saving until the latest version is loaded", async ({
    browser,
  }) => {
    const username = uniqueUsername();
    const a = await (await browser.newContext()).newPage();
    const b = await (await browser.newContext()).newPage();
    await register(a, username);
    await login(a, username);
    await addTable(a);
    await login(b, username);

    await saved(a, () => renameTable(a, 0, "Alpha"));
    await renameTable(b, 0, "Beta");

    const banner = b.locator(".pm-conflict");
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("renamed differently");
    await expect(b.locator("span[name='stat-span']")).toContainText(
      "Saving paused",
    );

    await banner.locator("button:has-text('Load latest version')").click();
    await expect(banner).toBeHidden();
    await expect(tableNames(b)).toHaveText(["Alpha"]);

    // saving works again
    await saved(b, () => renameTable(b, 0, "Gamma"));
    const c = await (await browser.newContext()).newPage();
    await login(c, username);
    await expect(tableNames(c)).toHaveText(["Gamma"]);
  });
});

test.describe("Vault contents", () => {
  test("links must use an allowed scheme", async ({ page }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username);
    await addTable(page);

    await saved(page, async () => {
      await page.click(".pm-card-header button:has-text('Add Column')");
      await page.fill(".pm-modal input[type='text']", "Site");
      await page.locator(".pm-modal select").selectOption("link");
      await page.click(".pm-modal button:has-text('Add Column')");
    });
    await saved(page, () =>
      page.click(".pm-card-header button:has-text('Add Row')"),
    );

    const cell = page.locator("td.pm-td-data").first();
    await cell.focus();
    await cell.press("Enter");
    const urlInput = cell.locator("input").first();

    await urlInput.fill("javascript:alert(1)");
    await urlInput.press("Enter");
    // not saved: the cell stays in edit mode with the error shown
    await expect(urlInput).toBeVisible();
    await expect(cell).toContainText("URL must start with one of");

    await saved(page, async () => {
      await urlInput.fill("mailto:someone@example.com");
      await urlInput.press("Enter");
    });
    const link = cell.locator("a");
    await expect(link).toHaveAttribute("href", "mailto:someone@example.com");
    await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  test("a generated password added to a table is saved", async ({ page }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username);
    await addTable(page);

    await page.click("#passgen-panel button[name='generate']");
    await page
      .locator("#passgen-panel select[name='password-add-table']")
      .selectOption("New Table");
    await saved(page, () =>
      page.click("#passgen-panel button[name='add-to-table']"),
    );
    await expect(page.locator(".pm-table tbody tr")).toHaveCount(1);

    await page.click("button[name='logout']");
    await login(page, username);
    await expect(page.locator(".pm-table tbody tr")).toHaveCount(1);
  });

  test("logout removes the vault from the page", async ({ page }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username);
    await addTable(page);
    await saved(page, () => renameTable(page, 0, "Secret Table"));

    await page.click("button[name='logout']");
    await expect(page.locator("div[name='data']")).toBeEmpty();
    expect(await page.content()).not.toContain("Secret Table");
    await expect(page.locator("#login-password")).toHaveValue("");
  });
});
