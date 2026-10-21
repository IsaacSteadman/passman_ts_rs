import { test, expect, type Page } from "@playwright/test";

/** Light and dark appearance: following the device, or chosen on it. */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

const LIGHT_BG = "rgb(243, 244, 246)";
const DARK_BG = "rgb(17, 24, 39)";

function uniqueUsername(): string {
  return `t${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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

const pageBackground = (page: Page) =>
  page.evaluate(() => getComputedStyle(document.body).backgroundColor);
const barColors = (page: Page) =>
  page
    .locator("meta[name='theme-color']")
    .evaluateAll((metas) =>
      metas.map((meta) => (meta as HTMLMetaElement).content),
    );

test.describe("Appearance", () => {
  test("follows the device by default", async ({ browser }) => {
    for (const [colorScheme, background] of [
      ["light", LIGHT_BG],
      ["dark", DARK_BG],
    ] as const) {
      const context = await browser.newContext({ colorScheme });
      const page = await context.newPage();
      await page.goto(START);
      expect(await pageBackground(page)).toBe(background);
      await context.close();
    }
  });

  test("a theme chosen on the device overrides it and is kept", async ({
    browser,
  }) => {
    // no service worker, so blocking the app's script below is reliable
    const context = await browser.newContext({
      colorScheme: "light",
      serviceWorkers: "block",
    });
    const page = await context.newPage();
    await registerAndLogin(page, uniqueUsername());
    await page.click("details[name='this-device'] summary");
    const select = page.locator("select[name='theme']");
    await expect(select).toHaveValue("auto");

    await select.selectOption("dark");
    expect(await pageBackground(page)).toBe(DARK_BG);
    expect(await barColors(page)).toEqual(["#1f2937", "#1f2937"]);

    // applied from the first paint after reopening, before the app script runs
    await page.route(/\.js$/, (route) => route.abort());
    await page.reload({ waitUntil: "domcontentloaded" });
    expect(await pageBackground(page)).toBe(DARK_BG);
    await context.close();
  });

  test("going back to matching the device", async ({ browser }) => {
    const context = await browser.newContext({ colorScheme: "dark" });
    const page = await context.newPage();
    await registerAndLogin(page, uniqueUsername());
    await page.click("details[name='this-device'] summary");
    const select = page.locator("select[name='theme']");
    await select.selectOption("light");
    expect(await pageBackground(page)).toBe(LIGHT_BG);
    await select.selectOption("auto");
    expect(await pageBackground(page)).toBe(DARK_BG);
    expect(await barColors(page)).toEqual(["#ffffff", "#1f2937"]);
    await context.close();
  });
});
