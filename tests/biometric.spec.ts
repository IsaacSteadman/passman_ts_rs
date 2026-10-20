import { test, expect, type Page, type Response } from "@playwright/test";

/**
 * Biometric unlock, using Chromium's virtual authenticator in place of Face ID
 * / a fingerprint reader. Each test registers its own user.
 */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";
const NEW_PASSWORD = "battery staple";

function uniqueUsername(): string {
  return `b${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

/** Adds a platform authenticator with user verification ("biometrics"). */
async function addAuthenticator(page: Page, { hasPrf = true } = {}) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf,
        automaticPresenceSimulation: true,
      },
    },
  );
  return {
    /** Makes the next biometric checks fail (or pass again). */
    setVerified: (isUserVerified: boolean) =>
      cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified }),
  };
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

async function loginRemembered(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.check("#login input[name='remember']");
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

const biometricStatus = (page: Page) =>
  page.locator("[name='biometric-status']");
const tableNames = (page: Page) => page.locator(".pm-card-name");

async function turnOnBiometrics(page: Page): Promise<void> {
  await page.click("details[name='this-device'] summary");
  await page.click("button[name='enable-biometric']");
  await expect(biometricStatus(page)).toContainText("Biometric unlock is on");
}

/** Sets up a remembered account with one table and biometric unlock on. */
async function setUp(page: Page, username: string): Promise<void> {
  await register(page, username);
  await loginRemembered(page, username);
  await saved(page, () => page.click("button:has-text('Add Table')"));
  await turnOnBiometrics(page);
}

test.describe("Biometric unlock", () => {
  test("unlocks a remembered account, also offline", async ({ browser }) => {
    const username = uniqueUsername();
    const context = await browser.newContext();
    const page = await context.newPage();
    await addAuthenticator(page);
    await setUp(page, username);
    await page.evaluate(() => navigator.serviceWorker.ready);
    await page.waitForFunction(
      () => navigator.serviceWorker.controller != null,
    );
    await page.click("button[name='logout']");

    await context.setOffline(true);
    await page.reload();
    // tapping the account asks for biometrics straight away
    await page.click(`.pm-account:has-text('${username}')`);
    await expect(page.locator("#content")).toBeVisible();
    await expect(tableNames(page)).toHaveText(["New Table"]);
    await context.close();
  });

  test("a failed biometric check leaves the password as the way in", async ({
    page,
  }) => {
    const username = uniqueUsername();
    const authenticator = await addAuthenticator(page);
    await setUp(page, username);
    await page.click("button[name='logout']");

    await authenticator.setVerified(false);
    await page.click(`.pm-account:has-text('${username}')`);
    await expect(page.locator("#error-panel")).toContainText(
      "cancelled or timed out",
    );
    await expect(page.locator("#content")).toBeHidden();

    await page.fill("#unlock-password", PASSWORD);
    await page.click("#remembered input[name='unlock']");
    await expect(tableNames(page)).toHaveText(["New Table"]);
  });

  test("after a password change it is confirmed again with the new keys", async ({
    page,
  }) => {
    const username = uniqueUsername();
    await addAuthenticator(page);
    await setUp(page, username);

    await page.click("details[name='change-password'] summary");
    await page.fill("#chg-current-pass", PASSWORD);
    await page.fill("#chg-new-pass", NEW_PASSWORD);
    await page.fill("#chg-confirm-pass", NEW_PASSWORD);
    await page.click("input[name='submit-chg-pass']");
    await expect(page.locator("span[name='chg-pass-status']")).toHaveText(
      "Password changed successfully.",
    );
    await expect(biometricStatus(page)).toContainText("confirmed again");

    // until confirmed, the lock screen only offers the password
    await page.click("button[name='logout']");
    await page.click(`.pm-account:has-text('${username}')`);
    await expect(page.locator(".pm-biometric-unlock")).toBeHidden();
    await page.fill("#unlock-password", NEW_PASSWORD);
    await page.click("#remembered input[name='unlock']");
    await expect(page.locator("#content")).toBeVisible();

    await page.click("details[name='this-device'] summary");
    await page.click("button[name='update-biometric']");
    await expect(biometricStatus(page)).toContainText("Biometric unlock is on");
    await page.click("button[name='logout']");
    await page.click(`.pm-account:has-text('${username}')`);
    await expect(tableNames(page)).toHaveText(["New Table"]);
  });

  test("is refused when passkeys don't support PRF", async ({ page }) => {
    const username = uniqueUsername();
    await addAuthenticator(page, { hasPrf: false });
    await register(page, username);
    await loginRemembered(page, username);
    await page.click("details[name='this-device'] summary");
    await page.click("button[name='enable-biometric']");
    await expect(page.locator("[name='biometric-message']")).toContainText(
      "don't support the PRF extension",
    );
    await expect(page.locator("button[name='enable-biometric']")).toBeVisible();
    expect(await storedUnlockKeys(page)).toEqual([]);
  });

  test("the stored keys are encrypted with a key that can't be exported", async ({
    page,
  }) => {
    const username = uniqueUsername();
    await addAuthenticator(page);
    await setUp(page, username);
    const [record] = await storedUnlockKeys(page);
    expect(record).toEqual({ deviceKeyExtractable: false, wrapped: true });
  });

  test("turning it off removes it from the lock screen", async ({ page }) => {
    const username = uniqueUsername();
    await addAuthenticator(page);
    await setUp(page, username);
    await page.click("button[name='disable-biometric']");
    await expect(page.locator("button[name='enable-biometric']")).toBeVisible();
    expect(await storedUnlockKeys(page)).toEqual([]);

    await page.click("button[name='logout']");
    await page.click(`.pm-account:has-text('${username}')`);
    await expect(page.locator(".pm-biometric-unlock")).toBeHidden();
  });
});

/** A summary of each biometric unlock record stored on the device. */
async function storedUnlockKeys(
  page: Page,
): Promise<{ deviceKeyExtractable: boolean; wrapped: boolean }[]> {
  return page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("passman");
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const request = open.result
            .transaction("unlockKeys")
            .objectStore("unlockKeys")
            .getAll();
          request.onerror = () => reject(request.error);
          request.onsuccess = () =>
            resolve(
              (
                request.result as {
                  deviceKey: CryptoKey;
                  wrapped: unknown;
                }[]
              ).map((record) => ({
                deviceKeyExtractable: record.deviceKey.extractable,
                wrapped: record.wrapped != null,
              })),
            );
        };
      }),
  );
}
