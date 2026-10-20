import { test, expect, type Page, type Response } from "@playwright/test";

/** Auto-lock: after being idle, and when the app is hidden. */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

function uniqueUsername(): string {
  return `l${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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
  { remember = false } = {},
): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  if (remember) await page.check("#login input[name='remember']");
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

async function addTable(page: Page): Promise<void> {
  const ok = page.waitForResponse(
    (r: Response) => r.request().method() === "PUT" && r.status() === 200,
  );
  await page.click("button:has-text('Add Table')");
  await ok;
}

/** Makes the page believe it was hidden (app switched away, screen off). */
async function hide(page: Page): Promise<void> {
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

const content = (page: Page) => page.locator("#content");

test.describe("Auto-lock", () => {
  test("locks after 5 idle minutes by default", async ({ page }) => {
    const username = uniqueUsername();
    await page.clock.install();
    await register(page, username);
    await login(page, username, { remember: true });
    await addTable(page);
    await expect(page.locator("button[name='logout']")).toHaveText("Lock");

    await page.clock.fastForward("04:00");
    await expect(content(page)).toBeVisible();
    // input restarts the idle period
    await page.locator("span[name='stat-span']").click();
    await page.clock.fastForward("04:00");
    await expect(content(page)).toBeVisible();

    await page.clock.fastForward("01:30");
    await expect(content(page)).toBeHidden();
    expect(await page.content()).not.toContain("New Table");
    // the locked account is ready to unlock again
    await expect(page.locator(".pm-unlock-account")).toHaveText(
      `Unlock ${username}`,
    );
    await page.fill("#unlock-password", PASSWORD);
    await page.click("#remembered input[name='unlock']");
    await expect(page.locator(".pm-card-name")).toHaveText(["New Table"]);
  });

  test("locks when the app is hidden, unless turned off", async ({ page }) => {
    const username = uniqueUsername();
    await register(page, username);
    await login(page, username);
    await hide(page);
    await expect(content(page)).toBeHidden();
    await expect(page.locator("#login")).toBeVisible();

    await login(page, username);
    await page.click("details[name='this-device'] summary");
    await page.uncheck("input[name='lock-when-hidden']");
    await hide(page);
    await expect(content(page)).toBeVisible();

    // the setting belongs to the device: it's kept after reloading
    await page.reload();
    await login(page, username);
    await page.click("details[name='this-device'] summary");
    await expect(
      page.locator("input[name='lock-when-hidden']"),
    ).not.toBeChecked();
  });

  test("never locks when idle if set to Never", async ({ page }) => {
    const username = uniqueUsername();
    await page.clock.install();
    await register(page, username);
    await login(page, username);
    await page.click("details[name='this-device'] summary");
    await page.selectOption("select[name='idle-lock']", "never");
    await page.clock.fastForward("02:00:00");
    await expect(content(page)).toBeVisible();
  });

  test("doesn't lock while unsaved changes exist only in the page", async ({
    browser,
  }) => {
    const username = uniqueUsername();
    const context = await browser.newContext();
    const page = await context.newPage();
    await register(page, username);
    await login(page, username);
    await addTable(page);

    await context.setOffline(true);
    const nameEl = page.locator(".pm-card-name").first();
    await nameEl.fill("Unsaved");
    await nameEl.press("Enter");
    await expect(page.locator("span[name='stat-span']")).toContainText(
      "Offline",
    );
    await hide(page);
    await expect(content(page)).toBeVisible();
    await expect(page.locator("span[name='stat-span']")).toContainText(
      "Not locked automatically",
    );
    await context.close();
  });
});
