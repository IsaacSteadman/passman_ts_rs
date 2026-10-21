import {
  test,
  expect,
  type Browser,
  type Page,
  type Response,
} from "@playwright/test";
import { readFile } from "node:fs/promises";

/** Import & Export: backups, unencrypted exports and CSV files from other
 *  password managers. Each test registers its own users. */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";
const BACKUP_PASSWORD = "backup staple";

function uniqueUsername(): string {
  return `x${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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
  await login(page, username);
}

async function login(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

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

const panel = (page: Page) => page.locator("details[name='import-export']");
const importStatus = (page: Page) => page.locator("[name='import-status']");
const tableNames = (page: Page) => page.locator(".pm-card-name");

async function openPanel(page: Page): Promise<void> {
  const details = panel(page);
  if (!(await details.evaluate((el) => (el as HTMLDetailsElement).open)))
    await details.locator("summary").click();
}

async function chooseFile(
  page: Page,
  name: string,
  contents: string,
): Promise<void> {
  await openPanel(page);
  await page.setInputFiles("input[name='import-file']", {
    name,
    mimeType: "text/plain",
    buffer: Buffer.from(contents),
  });
}

async function confirmImport(page: Page): Promise<void> {
  await saved(page, () => page.click("button[name='confirm-import']"));
  await expect(importStatus(page)).toContainText("Imported");
}

async function namesOnServer(
  browser: Browser,
  username: string,
): Promise<string[]> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await login(page, username);
  const names = await tableNames(page).allTextContents();
  await context.close();
  return names;
}

/** Makes the page believe it was hidden or shown again. */
async function setVisibility(page: Page, state: "hidden" | "visible") {
  await page.evaluate((state) => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => state,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  }, state);
}

const CHROME_CSV = [
  "name,url,username,password,note",
  "Example,https://example.com/login,alice,hunter2,",
  "",
].join("\r\n");

test.describe("Import & Export", () => {
  test("imports a Bitwarden CSV", async ({ browser }) => {
    const context = await browser.newContext({
      permissions: ["clipboard-read", "clipboard-write"],
    });
    const page = await context.newPage();
    const username = uniqueUsername();
    await registerAndLogin(page, username);

    await chooseFile(
      page,
      "bitwarden.csv",
      [
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp",
        'Work,1,login,Example,"line one\nline two, with a comma",,0,example.com,alice,"pa""ss,word",otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example',
        ",,login,Odd link,,,0,javascript:alert(1),bob,hunter2,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8",
      ].join("\n"),
    );
    const preview = page.locator("[name='import-preview']");
    await expect(preview).toContainText("2 entries in 1 table");
    await expect(preview).toContainText("Imported from bitwarden.csv");
    await expect(preview).toContainText("1 MFA key uses code settings");
    await confirmImport(page);

    await expect(tableNames(page)).toHaveText(["Imported from bitwarden.csv"]);
    await expect(page.locator("table.pm-table th")).toHaveText([
      "Name",
      "Site",
      "Username",
      "Password",
      "MFA Key",
      "Notes",
      "folder",
      "",
    ]);
    const rows = page.locator("table.pm-table tbody tr");
    // a domain without a scheme becomes https; other schemes aren't links
    await expect(rows.nth(0).locator("a")).toHaveAttribute(
      "href",
      "https://example.com",
    );
    await expect(rows.nth(1).locator("a")).toHaveCount(0);
    await expect(rows.nth(1)).toContainText("javascript:alert(1)");
    await expect(rows.nth(0)).toContainText("line two, with a comma");

    await rows.nth(0).locator("button[title='Copy password']").click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
      'pa"ss,word',
    );
    expect(await namesOnServer(browser, username)).toEqual([
      "Imported from bitwarden.csv",
    ]);
    await context.close();
  });

  test("an encrypted backup restores into another account", async ({
    browser,
  }) => {
    const contextA = await browser.newContext();
    const a = await contextA.newPage();
    await registerAndLogin(a, uniqueUsername());
    await chooseFile(a, "chrome.csv", CHROME_CSV);
    await confirmImport(a);

    await a.fill("input[name='backup-pass']", BACKUP_PASSWORD);
    await a.fill("input[name='backup-pass-confirm']", "something else");
    await a.click("button[name='download-backup']");
    await expect(a.locator("[name='backup-status']")).toHaveText(
      "The passwords don't match.",
    );
    await a.fill("input[name='backup-pass-confirm']", BACKUP_PASSWORD);
    const [download] = await Promise.all([
      a.waitForEvent("download"),
      a.click("button[name='download-backup']"),
    ]);
    expect(download.suggestedFilename()).toMatch(
      /^passman-backup-\d{4}-\d{2}-\d{2}\.passman$/,
    );
    const backup = await readFile(await download.path(), "utf8");
    expect(JSON.parse(backup)).toMatchObject({
      format: "passman-backup",
      version: 1,
    });
    // nothing readable in it
    for (const secret of ["hunter2", "alice", "example.com", "Imported"])
      expect(backup).not.toContain(secret);
    await contextA.close();

    const contextB = await browser.newContext();
    const b = await contextB.newPage();
    const usernameB = uniqueUsername();
    await registerAndLogin(b, usernameB);
    await chooseFile(b, "backup.passman", backup);
    await b.fill("input[name='import-pass']", "wrong");
    await b.click("button[name='unlock-import']");
    await expect(importStatus(b)).toHaveText(
      "Wrong backup password, or a damaged backup.",
    );
    await b.fill("input[name='import-pass']", BACKUP_PASSWORD);
    await b.press("input[name='import-pass']", "Enter");
    await expect(b.locator("[name='import-preview']")).toContainText(
      "1 entry in 1 table",
    );
    await confirmImport(b);
    await expect(tableNames(b)).toHaveText(["Imported from chrome.csv"]);
    expect(await namesOnServer(browser, usernameB)).toEqual([
      "Imported from chrome.csv",
    ]);
    await contextB.close();
  });

  test("an unencrypted export has the tables but not the history", async ({
    page,
  }) => {
    await registerAndLogin(page, uniqueUsername());
    await chooseFile(page, "chrome.csv", CHROME_CSV);
    await confirmImport(page);

    let warned = "";
    page.once("dialog", (dialog) => {
      warned = dialog.message();
      void dialog.accept();
    });
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click("button[name='download-export']"),
    ]);
    expect(warned).toContain("won't be encrypted");
    const exported = JSON.parse(await readFile(await download.path(), "utf8"));
    expect(exported.format).toBe("passman-export");
    expect(exported.history).toBeUndefined();
    expect(exported.tables[0].name).toBe("Imported from chrome.csv");

    // importing it again adds a copy under another name
    await chooseFile(page, "export.json", JSON.stringify(exported));
    await confirmImport(page);
    await expect(tableNames(page)).toHaveText([
      "Imported from chrome.csv",
      "Imported from chrome.csv (imported)",
    ]);

    // and it can be undone from History
    await page.click("details[name='history'] summary");
    await saved(page, () =>
      page
        .locator(".pm-history-list > div")
        .filter({ hasText: "(imported)" })
        .locator("button")
        .click(),
    );
    await expect(tableNames(page)).toHaveText(["Imported from chrome.csv"]);
  });

  test("choosing a file doesn't lock the app", async ({ page }) => {
    await registerAndLogin(page, uniqueUsername());
    await openPanel(page);
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      page.click("input[name='import-file']"),
    ]);
    // on phones the system picker hides the app
    await setVisibility(page, "hidden");
    await expect(page.locator("#content")).toBeVisible();
    await setVisibility(page, "visible");
    await chooser.setFiles({
      name: "chrome.csv",
      mimeType: "text/csv",
      buffer: Buffer.from(CHROME_CSV),
    });
    await expect(page.locator("[name='import-preview']")).toBeVisible();

    // afterwards, hiding the app locks it again
    await setVisibility(page, "hidden");
    await expect(page.locator("#content")).toBeHidden();
  });

  test("files that aren't exports are refused", async ({ page }) => {
    await registerAndLogin(page, uniqueUsername());
    await chooseFile(page, "other.json", '{"hello": "world"}');
    await expect(importStatus(page)).toHaveText(
      "This isn't a Passman export or backup.",
    );
    await chooseFile(
      page,
      "damaged.json",
      JSON.stringify({
        format: "passman-export",
        version: 1,
        tables: [
          {
            name: "T",
            columns: [
              { label: "A", type: "textarea", data: ["1", "2"] },
              { label: "B", type: "textarea", data: ["1"] },
            ],
          },
        ],
      }),
    );
    await expect(importStatus(page)).toHaveText(
      "Table 1 has columns of different lengths.",
    );
    await chooseFile(page, "notes.csv", "title,body\nhello,world\n");
    await expect(importStatus(page)).toContainText(
      "No username or password column found",
    );
    await expect(page.locator("button[name='confirm-import']")).toBeHidden();
    await expect(tableNames(page)).toHaveCount(0);
  });
});
