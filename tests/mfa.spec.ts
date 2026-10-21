import { test, expect, type Page, type Response } from "@playwright/test";

/** MFA codes in the tables: shown with a countdown, or copied. Uses the
 *  RFC 6238 test key and times, so the codes are known. */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";
const RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

function uniqueUsername(): string {
  return `m${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

async function setUp(page: Page): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.click("#login .pm-auth-tab:has-text('Register')");
  const username = uniqueUsername();
  await page.fill("#register input[name='username']", username);
  await page.fill("#register input[name='new_pass']", PASSWORD);
  await page.fill("#register input[name='confirm_new_pass']", PASSWORD);
  await page.click("#register input[name='submit']");
  await expect(page.locator("#error-panel")).toContainText("Account created");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();

  await page.click("details[name='import-export'] summary");
  await page.setInputFiles("input[name='import-file']", {
    name: "keys.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(
      [
        "name,username,totp",
        `RFC,alice,${RFC_KEY}`,
        "Broken,bob,not base32!",
      ].join("\n"),
    ),
  });
  const ok = page.waitForResponse(
    (r: Response) => r.request().method() === "PUT" && r.status() === 200,
  );
  await page.click("button[name='confirm-import']");
  await ok;
}

const row = (page: Page, index: number) =>
  page.locator("table.pm-table tbody tr").nth(index);

test.describe("MFA codes", () => {
  test("shows the code with the time left, and copies it", async ({
    browser,
  }) => {
    const context = await browser.newContext({
      permissions: ["clipboard-read", "clipboard-write"],
    });
    const page = await context.newPage();
    await setUp(page);
    const cell = row(page, 0);
    const masked = cell.getByText("MFA Key: ••••");
    await expect(masked).toBeVisible();
    await expect(cell.locator(".pm-otp")).toBeHidden();

    // one second before the code changes
    await page.clock.setFixedTime(new Date(1111111109_000));
    await cell.locator("button[title='Show code']").click();
    await expect(cell.locator(".pm-otp-code")).toHaveText("081 804");
    await expect(cell.locator(".pm-otp-timer")).toHaveText("1");
    await expect(cell.locator(".pm-otp-timer")).toHaveClass(/pm-otp-expiring/);
    await expect(masked).toBeHidden();

    // the next code appears when the period ends
    await page.clock.setFixedTime(new Date(1111111111_000));
    await expect(cell.locator(".pm-otp-code")).toHaveText("050 471");
    await expect(cell.locator(".pm-otp-timer")).toHaveText("29");
    await expect(cell.locator(".pm-otp-timer")).not.toHaveClass(
      /pm-otp-expiring/,
    );

    // copying still copies the current code
    await cell.locator("button[title='Copy code']").click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
      "050471",
    );

    await cell.locator("button[title='Hide code']").click();
    await expect(cell.locator(".pm-otp")).toBeHidden();
    await expect(masked).toBeVisible();
    await context.close();
  });

  test("an invalid key says so instead of showing a code", async ({ page }) => {
    await setUp(page);
    const cell = row(page, 1);
    await cell.locator("button[title='Show code']").click();
    await expect(cell.locator(".pm-otp-code")).toHaveText("Invalid MFA key");
  });
});
