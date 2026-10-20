import {
  test,
  expect,
  type Browser,
  type Page,
  type Response,
} from "@playwright/test";

/**
 * Accounts remembered on the device: unlocking and editing offline, syncing
 * when back online, and a password changed in another session. Each test
 * registers its own user.
 */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";
const NEW_PASSWORD = "battery staple";

function uniqueUsername(): string {
  return `o${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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

async function login(
  page: Page,
  username: string,
  { remember = false, password = PASSWORD } = {},
): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", password);
  if (remember) await page.check("#login input[name='remember']");
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

/** Unlocks an account from the "On this device" list. */
async function unlock(
  page: Page,
  username: string,
  password = PASSWORD,
): Promise<void> {
  await page.click(`.pm-account:has-text('${username}')`);
  await page.fill("#unlock-password", password);
  await page.click("#remembered input[name='unlock']");
}

/** Waits until the service worker controls the page, so it works offline. */
async function waitForServiceWorker(page: Page): Promise<void> {
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.waitForFunction(() => navigator.serviceWorker.controller != null);
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

async function renameTable(page: Page, index: number, name: string) {
  const nameEl = page.locator(".pm-card-name").nth(index);
  await nameEl.fill(name);
  await nameEl.press("Enter");
}

const tableNames = (page: Page) => page.locator(".pm-card-name");
const status = (page: Page) => page.locator("span[name='stat-span']");

/** The table names a fresh session sees after logging in. */
async function namesOnServer(
  browser: Browser,
  username: string,
  password = PASSWORD,
): Promise<string[]> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await login(page, username, { password });
  const names = await tableNames(page).allTextContents();
  await context.close();
  return names;
}

async function changePassword(page: Page, from: string, to: string) {
  await page.click("details[name='change-password'] summary");
  await page.fill("#chg-current-pass", from);
  await page.fill("#chg-new-pass", to);
  await page.fill("#chg-confirm-pass", to);
  await page.click("input[name='submit-chg-pass']");
  await expect(page.locator("span[name='chg-pass-status']")).toHaveText(
    "Password changed successfully.",
  );
}

test.describe("Remembered accounts", () => {
  test("unlock and edit offline, then save when back online", async ({
    browser,
  }) => {
    const username = uniqueUsername();
    const context = await browser.newContext();
    const page = await context.newPage();
    await register(page, username);
    await login(page, username, { remember: true });
    await waitForServiceWorker(page);
    await saved(page, () => page.click("button:has-text('Add Table')"));
    await page.click("button[name='logout']");
    await expect(page.locator(".pm-account")).toHaveText(username);

    // offline: the app loads from the service worker and the vault from the
    // device
    await context.setOffline(true);
    await page.reload();
    await unlock(page, username);
    await expect(tableNames(page)).toHaveText(["New Table"]);
    await renameTable(page, 0, "Edited Offline");
    await expect(status(page)).toContainText("Offline");

    // the change survives closing the app
    await page.reload();
    await unlock(page, username);
    await expect(tableNames(page)).toHaveText(["Edited Offline"]);

    // back online: the change is saved
    const ok = page.waitForResponse(
      (r) => r.request().method() === "PUT" && r.status() === 200,
    );
    await context.setOffline(false);
    await ok;
    expect(await namesOnServer(browser, username)).toEqual(["Edited Offline"]);
    await context.close();
  });

  test("a wrong password doesn't unlock offline", async ({ browser }) => {
    const username = uniqueUsername();
    const context = await browser.newContext();
    const page = await context.newPage();
    await register(page, username);
    await login(page, username, { remember: true });
    await waitForServiceWorker(page);
    await page.click("button[name='logout']");

    await context.setOffline(true);
    await page.reload();
    await unlock(page, username, "wrong");
    await expect(page.locator("#error-panel")).toContainText("Wrong password");
    await expect(page.locator("#content")).toBeHidden();
    await context.close();
  });

  test("edits merge after the password was changed in another session", async ({
    browser,
  }) => {
    const username = uniqueUsername();
    const context = await browser.newContext();
    const a = await context.newPage();
    await register(a, username);
    await login(a, username, { remember: true });
    await waitForServiceWorker(a);
    await saved(a, () => a.click("button:has-text('Add Table')"));
    await a.click("button[name='logout']");

    // an edit made offline, then the password changed elsewhere
    await context.setOffline(true);
    await a.reload();
    await unlock(a, username);
    await renameTable(a, 0, "Edited Offline");
    await expect(status(a)).toContainText("Offline");
    await a.click("button[name='logout']");

    const otherContext = await browser.newContext();
    const b = await otherContext.newPage();
    await login(b, username);
    await saved(b, () => b.click("button:has-text('Add Table')"));
    await changePassword(b, PASSWORD, NEW_PASSWORD);
    await otherContext.close();

    // back online, the new password can't decrypt this device's unsaved
    // change, so the previous one is asked for
    await context.setOffline(false);
    await a.reload();
    await unlock(a, username, NEW_PASSWORD);
    await expect(a.locator("#error-panel")).toContainText(
      "Unlock with the previous password",
    );
    // the unlock form stays open after a failed attempt
    await a.fill("#unlock-password", PASSWORD);
    await a.click("#remembered input[name='unlock']");

    // the server rejects the old password; the new one merges both sessions
    const banner = a.locator(".pm-password-changed");
    await expect(banner).toBeVisible();
    await saved(a, async () => {
      await banner.locator("input").fill(NEW_PASSWORD);
      await banner.locator("button").click();
    });
    await expect(banner).toBeHidden();
    await expect(tableNames(a)).toHaveText(["Edited Offline", "New Table"]);
    expect(await namesOnServer(browser, username, NEW_PASSWORD)).toEqual([
      "Edited Offline",
      "New Table",
    ]);

    // and this device's copy now opens with the new password
    await a.click("button[name='logout']");
    await context.setOffline(true);
    await a.reload();
    await unlock(a, username, NEW_PASSWORD);
    await expect(tableNames(a)).toHaveText(["Edited Offline", "New Table"]);
    await context.close();
  });

  test("forgetting an account removes it from the device", async ({ page }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username, { remember: true });
    await page.click("details[name='this-device'] summary");
    await page.click("button[name='forget-device']");
    await expect(page.locator("button[name='remember-device']")).toBeVisible();
    await page.click("button[name='logout']");
    await expect(page.locator("#remembered")).toBeHidden();
    expect(await storedAccountCount(page)).toBe(0);
  });

  test("an account not remembered leaves nothing on the device", async ({
    page,
  }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username);
    await saved(page, () => page.click("button:has-text('Add Table')"));
    await page.click("button[name='logout']");
    await expect(page.locator("#remembered")).toBeHidden();
    expect(await storedAccountCount(page)).toBe(0);
  });
});

/** Number of entries in the device's account and vault stores. */
async function storedAccountCount(page: Page): Promise<number> {
  return page.evaluate(
    () =>
      new Promise<number>((resolve, reject) => {
        const open = indexedDB.open("passman");
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const stores = ["accounts", "vaults"].filter((name) =>
            db.objectStoreNames.contains(name),
          );
          if (stores.length === 0) return resolve(0);
          const tx = db.transaction(stores);
          let total = 0;
          for (const name of stores) {
            const count = tx.objectStore(name).count();
            count.onsuccess = () => (total += count.result);
          }
          tx.oncomplete = () => resolve(total);
        };
      }),
  );
}
