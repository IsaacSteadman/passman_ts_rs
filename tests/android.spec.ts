import {
  test,
  expect,
  _android as android,
  type AndroidDevice,
  type Page,
} from "@playwright/test";
import { execFileSync } from "node:child_process";
import path from "node:path";

/**
 * The Android app on an emulator (skipped without one): setting up the
 * server, biometric unlock with the Keystore, and autofill in another app
 * (android/demo). The emulator needs a screen lock and an enrolled
 * fingerprint, which `adb emu finger touch 1` then presents. The server is
 * reached as 10.0.2.2, the emulator's alias for this computer.
 *
 * Accounts are created with the web app in desktop Chromium.
 */
const ROOT = path.join(__dirname, "..");
const SERVER = "http://localhost:8080";
const SERVER_FROM_EMULATOR = "http://10.0.2.2:8080";
const PASSWORD = "correct horse";
const APP = "com.firaxite.passman";
const DEMO = "com.firaxite.passmandemo";
const RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const adb = path.join(
  process.env.ANDROID_HOME ??
    `${process.env.HOME}/.local/share/android-dev/sdk`,
  "platform-tools/adb",
);

let device: AndroidDevice;
const username = `a${Date.now()}${Math.floor(Math.random() * 1e6)}`;

/** Presents the enrolled fingerprint to the biometric prompt showing. */
async function touchFingerprint(title: string): Promise<void> {
  await device.wait({ text: title });
  execFileSync(adb, ["-s", device.serial(), "emu", "finger", "touch", "1"]);
}

/** The app's page `file` (index.html or autofill.html). */
async function appPage(file: string): Promise<Page> {
  const webView = await device.webView({ pkg: APP }, { timeout: 30_000 });
  const context = (await webView.page()).context();
  let found: Page | undefined;
  await expect
    .poll(() => (found = context.pages().find((p) => p.url().endsWith(file))))
    .toBeTruthy();
  return found!;
}

const res = (id: string, pkg = APP) => ({ res: `${pkg}:id/${id}` });

/** Picks "Fill with Passman" in the demo app's `field`. Right after the app
 *  starts, focusing a field doesn't always show it: then it's picked in the
 *  `other` field (it fills them all). */
async function chooseFill(field: string, other: string): Promise<void> {
  await device.tap(res(field, DEMO));
  try {
    await device.wait({ text: "Fill with Passman" }, { timeout: 5_000 });
  } catch {
    await device.tap(res(other, DEMO));
  }
  await device.tap({ text: "Fill with Passman" });
}

test.describe.serial("Android app", () => {
  test.setTimeout(180_000);

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(600_000);
    const [found] = await android.devices();
    test.skip(found == null, "no Android device or emulator");
    device = found;
    execFileSync("node", ["scripts/build-android.mjs"], {
      cwd: ROOT,
      stdio: "ignore",
    });
    for (const apk of [
      "android/app/build/outputs/apk/debug/app-debug.apk",
      "android/demo/build/outputs/apk/debug/demo-debug.apk",
    ])
      await device.installApk(path.join(ROOT, apk));
    await device.shell(`pm clear ${APP}`);
    await device.shell(
      `settings put secure autofill_service ${APP}/.autofill.PassmanAutofillService`,
    );

    // an account with a login that has an MFA key
    const page = await browser.newPage();
    await page.goto(`${SERVER}/?server_pass=test`);
    await page.click("#login .pm-auth-tab:has-text('Register')");
    await page.fill("#register input[name='username']", username);
    await page.fill("#register input[name='new_pass']", PASSWORD);
    await page.fill("#register input[name='confirm_new_pass']", PASSWORD);
    await page.click("#register input[name='submit']");
    await expect(page.locator("#error-panel")).toContainText("Account created");
    await page.fill("#login-username", username);
    await page.fill("#login-password", PASSWORD);
    await page.click("#login input[name='submit']");
    await page.click("details[name='import-export'] summary");
    await page.setInputFiles("input[name='import-file']", {
      name: "logins.csv",
      mimeType: "text/csv",
      buffer: Buffer.from(
        `name,url,username,password,totp\nDemo,https://demo.example,alice,demo secret,${RFC_KEY}\n`,
      ),
    });
    const saved = page.waitForResponse(
      (r) => r.url().includes("/pass-table?") && r.request().method() === "PUT",
    );
    await page.click("button[name='confirm-import']");
    expect((await saved).status()).toBe(200);
    await page.close();
  });

  test.afterAll(async () => {
    await device?.close();
  });

  test("sets up the server and unlocks with the Keystore", async () => {
    await device.shell(`am start -W -n ${APP}/.MainActivity`);
    await device.fill(res("server"), SERVER_FROM_EMULATOR);
    await device.tap(res("connect"));
    await device.tap(res("use_server"));

    const page = await appPage("index.html");
    await expect(page.locator("[name='native-server']")).toHaveText(
      SERVER_FROM_EMULATOR,
    );
    // the app's own pages and nothing else: no network for the web view
    expect(
      await page.evaluate(() =>
        fetch("http://10.0.2.2:8080/").then(
          () => "reached",
          () => "blocked",
        ),
      ),
    ).toBe("blocked");

    await page.click(".pm-server-settings summary");
    await page.fill("#server-pass-inp", "test");
    await page.fill("#login-username", username);
    await page.fill("#login-password", PASSWORD);
    await page.check("#login input[name='remember']");
    await page.click("#login input[name='submit']");
    await expect(page.locator("#content")).toBeVisible({ timeout: 60_000 });
    await expect(page.locator(".pm-card-name")).toContainText([
      "Imported from logins.csv",
    ]);

    // no screenshots of it
    const windows = await device.shell("dumpsys window windows");
    expect(windows.toString()).toMatch(
      new RegExp(`${APP}/${APP}\\.MainActivity[\\s\\S]*?fl=[^\\n]*SECURE`),
    );

    await page.click("details[name='this-device'] summary");
    await page.click("button[name='enable-biometric']");
    await touchFingerprint("Turn on biometric unlock");
    await expect(page.locator("[name='biometric-status']")).toContainText(
      "Biometric unlock is on",
    );

    await page.click("button[name='logout']");
    await page.click(`.pm-account:has-text('${username}')`);
    await touchFingerprint("Unlock Passman");
    await expect(page.locator("#content")).toBeVisible();
    await expect(page.locator(".pm-card-name")).toContainText([
      "Imported from logins.csv",
    ]);
  });

  test("fills a login into an app once it's linked to it", async () => {
    await device.shell(`am start -S -W -n ${DEMO}/.LoginActivity`);
    await chooseFill("username", "password");
    // biometrics are on, so the check starts straight away
    await touchFingerprint("Unlock Passman");
    let page = await appPage("autofill.html");
    await expect(page.locator("[name='list-title']")).toHaveText(
      "No logins saved for Passman Demo (app)",
    );
    await page.fill("input[name='search']", "demo");
    const result = page.locator("ul[name='results'] .af-login");
    await result.locator("button:has-text('Use for this app')").click();
    // demo.example can't vouch for it
    await expect(result).toContainText("None of this login's sites list");
    const saved = page.waitForEvent("close");
    await result.locator("button:has-text('Fill and remember')").click();
    await saved;

    await device.wait({ ...res("username", DEMO), text: "alice" });
    await device.tap(res("sign_in", DEMO));
    const signedIn = await device.info(res("result", DEMO));
    expect(signedIn.text).toMatch(
      /^Signed in as alice with 11 characters, code \d{6}$/,
    );

    // linked now: offered straight away
    await device.shell(`am start -S -W -n ${DEMO}/.LoginActivity`);
    await chooseFill("password", "username");
    await touchFingerprint("Unlock Passman");
    page = await appPage("autofill.html");
    await expect(page.locator("[name='list-title']")).toHaveText(
      "Logins for Passman Demo (app)",
    );
    await page.click("ul[name='logins'] button:has-text('Fill')");
    await device.wait({ ...res("username", DEMO), text: "alice" });
    await device.tap(res("sign_in", DEMO));
    expect((await device.info(res("result", DEMO))).text).toContain(
      "Signed in as alice with 11 characters",
    );
  });

  test("saves a login typed into an app", async ({ page: web }) => {
    await device.shell(`am start -S -W -n ${DEMO}/.LoginActivity`);
    await device.fill(res("username", DEMO), "bob");
    await device.fill(res("password", DEMO), "bob's secret");
    await device.tap(res("sign_in", DEMO));
    // Android asks first
    await device.wait({ text: "Save username and password to Passman?" });
    await device.tap({ res: "android:id/autofill_save_yes" });
    await touchFingerprint("Unlock Passman");
    const page = await appPage("autofill.html");
    await expect(page.locator("[name='save-summary']")).toHaveText(
      "Save bob for Passman Demo (app)?",
    );
    await page.selectOption("select[name='save-table']", "new");
    await page.click("button[name='save']");
    await expect(page.locator("#status")).toHaveText(
      "Saved the login for Passman Demo (app).",
    );
    await page.click("button[name='close']");

    // in the vault, linked to the app
    await web.goto(`${SERVER}/?server_pass=test`);
    await web.fill("#login-username", username);
    await web.fill("#login-password", PASSWORD);
    await web.click("#login input[name='submit']");
    const logins = web.locator(".pm-card:has(.pm-card-name:text-is('Logins'))");
    await expect(logins).toContainText("bob");
    await expect(logins).toContainText(`android://`);
    await expect(logins).toContainText(`@${DEMO}/`);
  });
});
