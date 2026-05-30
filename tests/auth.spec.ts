import { test, expect, type Page } from "@playwright/test";

/**
 * ?server_pass=test auto-fills the Server Password field via main.ts URL param
 * handling (ServerAccessPassword in config.json is "test").
 */
const START = "/?server_pass=test";

/** Log in with the known test user and wait for the content area to appear. */
async function login(page: Page): Promise<void> {
  await page.goto(START);
  // Wait for WASM binary to finish loading before interacting
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", "abcd");
  await page.fill("#login-password", "1234");
  await page.click("#login input[name='submit']");
  // Argon2 key derivation + network round-trip can take several seconds
  await expect(page.locator("#content")).toBeVisible({ timeout: 30_000 });
}

test.describe("Auth card", () => {
  test("visible on page load, content hidden", async ({ page }) => {
    await page.goto(START);
    await expect(page.locator(".pm-auth-card")).toBeVisible();
    await expect(page.locator("#login")).toBeVisible();
    await expect(page.locator("#content")).not.toBeVisible();
  });

  test("Register tab switches view, Login tab switches back", async ({
    page,
  }) => {
    await page.goto(START);
    // Scope clicks to the visible parent div to avoid ambiguous matches
    await page.click("#login .pm-auth-tab:has-text('Register')");
    await expect(page.locator("#register")).toBeVisible();
    await expect(page.locator("#login")).not.toBeVisible();
    await page.click("#register .pm-auth-tab:has-text('Login')");
    await expect(page.locator("#login")).toBeVisible();
    await expect(page.locator("#register")).not.toBeVisible();
  });

  test("eye icon toggles password field type", async ({ page }) => {
    await page.goto(START);
    const pass = page.locator("#login-password");
    await expect(pass).toHaveAttribute("type", "password");
    // Click the show-toggle label inside #login
    await page.locator("#login .pm-show-toggle").click();
    await expect(pass).toHaveAttribute("type", "text");
    await page.locator("#login .pm-show-toggle").click();
    await expect(pass).toHaveAttribute("type", "password");
  });
});

test.describe("Login flow", () => {
  test("valid credentials hide auth wrap and show content", async ({
    page,
  }) => {
    await login(page);
    await expect(page.locator(".pm-auth-wrap")).not.toBeVisible();
    await expect(page.locator(".pm-app-bar")).toBeVisible();
  });

  test("app bar contains brand, Save, and Logout after login", async ({
    page,
  }) => {
    await login(page);
    await expect(page.locator(".pm-app-bar-brand")).toContainText("Passman");
    await expect(page.locator("button[name='save']")).toBeVisible();
    await expect(page.locator("button[name='logout']")).toBeVisible();
  });

  test("data area is attached after login", async ({ page }) => {
    await login(page);
    await expect(page.locator("div[name='data']")).toBeAttached();
  });

  test("password generator section visible after login", async ({ page }) => {
    await login(page);
    await expect(page.locator(".pm-section-label")).toContainText(
      "Password Generator",
    );
    await expect(page.locator("#passgen-panel")).toBeVisible();
  });

  test("change password section is present and expandable", async ({
    page,
  }) => {
    await login(page);
    const details = page.locator("details[name='change-password']");
    await expect(details).toBeAttached();
    // Open the collapsible
    await details.locator("summary").click();
    await expect(page.locator("#chg-current-pass")).toBeVisible();
  });
});

test.describe("Logout flow", () => {
  test("logout restores auth card on Login tab", async ({ page }) => {
    await login(page);
    await page.click("button[name='logout']");
    await expect(page.locator(".pm-auth-wrap")).toBeVisible();
    await expect(page.locator("#login")).toBeVisible();
    await expect(page.locator("#register")).not.toBeVisible();
    await expect(page.locator("#content")).not.toBeVisible();
  });

  test("can log in again after logging out", async ({ page }) => {
    await login(page);
    await page.click("button[name='logout']");
    await expect(page.locator(".pm-auth-wrap")).toBeVisible();
    // Second login
    await login(page);
    await expect(page.locator(".pm-app-bar")).toBeVisible();
  });
});
