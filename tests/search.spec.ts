import { test, expect, type Page, type Response } from "@playwright/test";

/** Searching the vault. Entries are added by importing CSV files. */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

function uniqueUsername(): string {
  return `q${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

async function registerAndLogin(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.click("#login .pm-auth-tab:has-text('Register')");
  await page.fill("#register input[name='username']", username);
  await page.fill("#register input[name='new_pass']", PASSWORD);
  await page.fill("#register input[name='confirm_new_pass']", PASSWORD);
  await page.click("#register input[name='submit']");
  await expect(page.locator("#error-panel")).toContainText("Account created");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

async function importCsv(page: Page, name: string, lines: string[]) {
  const details = page.locator("details[name='import-export']");
  if (!(await details.evaluate((el) => (el as HTMLDetailsElement).open)))
    await details.locator("summary").click();
  await page.setInputFiles("input[name='import-file']", {
    name,
    mimeType: "text/csv",
    buffer: Buffer.from(lines.join("\n")),
  });
  const ok = page.waitForResponse(
    (r: Response) => r.request().method() === "PUT" && r.status() === 200,
  );
  await page.click("button[name='confirm-import']");
  await ok;
}

async function setUp(page: Page): Promise<void> {
  await registerAndLogin(page, uniqueUsername());
  await importCsv(page, "personal.csv", [
    "name,url,username,password,note",
    "GitHub,https://github.com,alice,ghp-secret,work account",
    "Café Bank,https://bank.example,alice,bank-secret,",
    "Mail,https://mail.example,bob,mail-pass,personal",
  ]);
  await importCsv(page, "work.csv", [
    "name,url,username,password",
    "Jira,https://jira.example,carol,jira-pass",
  ]);
}

const search = (page: Page) => page.locator("input[name='vault-search']");
const visibleTables = (page: Page) =>
  page.locator("div[name='data'] > div:not([hidden]) .pm-card-name");
const nothingFound = (page: Page) => page.locator("[name='search-empty']");

/** The first cell (the name) of each entry shown. */
async function shownNames(page: Page): Promise<string[]> {
  return page
    .locator("div[name='data'] > div:not([hidden]) tbody tr:not([hidden])")
    .evaluateAll((rows) =>
      rows.map((row) => (row as HTMLTableRowElement).cells[0].innerText),
    );
}

test.describe("Search", () => {
  test("shows only the matching entries", async ({ page }) => {
    await setUp(page);
    expect(await shownNames(page)).toEqual([
      "GitHub",
      "Café Bank",
      "Mail",
      "Jira",
    ]);

    await search(page).fill("alice");
    expect(await shownNames(page)).toEqual(["GitHub", "Café Bank"]);
    await expect(visibleTables(page)).toHaveText([
      "Imported from personal.csv",
    ]);

    // case and accents don't matter; every word must match
    await search(page).fill("CAFE");
    expect(await shownNames(page)).toEqual(["Café Bank"]);
    await search(page).fill("alice work");
    expect(await shownNames(page)).toEqual(["GitHub"]);

    // sites are searched, and a table's name matches all its entries
    await search(page).fill("mail.example");
    expect(await shownNames(page)).toEqual(["Mail"]);
    await search(page).fill("work.csv");
    expect(await shownNames(page)).toEqual(["Jira"]);
    await expect(nothingFound(page)).toBeHidden();

    // Escape clears the search
    await search(page).press("Escape");
    expect(await shownNames(page)).toHaveLength(4);
  });

  test("passwords aren't searched", async ({ page }) => {
    await setUp(page);
    await search(page).fill("ghp-secret");
    expect(await shownNames(page)).toEqual([]);
    await expect(visibleTables(page)).toHaveCount(0);
    await expect(nothingFound(page)).toHaveText(
      'Nothing matches "ghp-secret".',
    );
  });

  test('"/" jumps to the search box', async ({ page }) => {
    await setUp(page);
    // typing "/" in an editable field still types it
    const name = page.locator(".pm-card-name").first();
    await name.click();
    await page.keyboard.press("End");
    await page.keyboard.press("/");
    await expect(search(page)).not.toBeFocused();
    await expect(name).toContainText("personal.csv/");

    await page.evaluate(() => (document.activeElement as HTMLElement).blur());
    await page.keyboard.press("/");
    await expect(search(page)).toBeFocused();
    await expect(search(page)).toHaveValue("");
  });
});
