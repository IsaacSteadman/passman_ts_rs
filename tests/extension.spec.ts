import {
  test as base,
  expect,
  chromium,
  type BrowserContext,
  type Page,
  type Worker,
} from "@playwright/test";
import { execFileSync } from "node:child_process";
import path from "node:path";

/**
 * The Chromium extension, in its test build, which may reach every site so
 * no permission prompt shows (built before the tests; the wasm must be built
 * already). The popup is opened as a page, with the tab it works on in its
 * URL.
 */
const EXTENSION = path.join(__dirname, "../dist-extension/chromium-test");
const SERVER = "http://localhost:8080";
const PASSWORD = "correct horse";

const test = base.extend<{ context: BrowserContext; worker: Worker }>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await chromium.launchPersistentContext("", {
      channel: "chromium",
      args: [
        `--disable-extensions-except=${EXTENSION}`,
        `--load-extension=${EXTENSION}`,
      ],
    });
    await use(context);
    await context.close();
  },
  worker: async ({ context }, use) => {
    const worker =
      context.serviceWorkers()[0] ??
      (await context.waitForEvent("serviceworker"));
    await use(worker);
  },
});

test.beforeAll(() => {
  test.setTimeout(120_000);
  execFileSync("node", ["scripts/build-extension.mjs", "--test"], {
    cwd: path.join(__dirname, ".."),
    stdio: "ignore",
  });
});

function uniqueUsername(): string {
  return `x${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

async function register(page: Page, username: string): Promise<void> {
  await page.goto(`${SERVER}/?server_pass=test`);
  await page.waitForLoadState("networkidle");
  await page.click("#login .pm-auth-tab:has-text('Register')");
  await page.fill("#register input[name='username']", username);
  await page.fill("#register input[name='new_pass']", PASSWORD);
  await page.fill("#register input[name='confirm_new_pass']", PASSWORD);
  await page.click("#register input[name='submit']");
  await expect(page.locator("#error-panel")).toContainText("Account created");
}

const LOGIN_PAGE = `<!doctype html>
<form>
  <input name="user" autocomplete="username">
  <input name="pass" type="password" autocomplete="current-password">
  <button>Sign in</button>
</form>`;

/** Serves a login page for these (made-up) sites. */
async function serveSites(context: BrowserContext): Promise<void> {
  await context.route(/^https:\/\/[a-z.-]+\.test\//, (route) =>
    route.fulfill({ contentType: "text/html", body: LOGIN_PAGE }),
  );
}

/** Opens the popup for the tab showing `site`. */
async function openPopup(
  context: BrowserContext,
  worker: Worker,
  site: string,
): Promise<Page> {
  const tabId = await worker.evaluate(
    async (url) => (await chrome.tabs.query({ url }))[0]?.id,
    `${site}*`,
  );
  expect(tabId).toBeDefined();
  const popup = await context.newPage();
  const extensionId = new URL(worker.url()).host;
  await popup.goto(`chrome-extension://${extensionId}/popup.html?tab=${tabId}`);
  return popup;
}

async function unlock(popup: Page, username: string): Promise<void> {
  await popup.fill("input[name=server]", SERVER);
  await popup.fill("input[name=username]", username);
  await popup.fill("input[name=password]", PASSWORD);
  await popup.click("summary:has-text('Server access')");
  await popup.fill("input[name=server_pass]", "test");
  await popup.click("button:has-text('Unlock')");
  await expect(popup.locator("#unlocked")).toBeVisible();
}

test("saves a typed login, fills it in, and only on its own site", async ({
  context,
  worker,
}) => {
  const username = uniqueUsername();
  const app = await context.newPage();
  await register(app, username);
  await serveSites(context);

  const site = await context.newPage();
  await site.goto("https://login.example.test/signin");
  let popup = await openPopup(context, worker, "https://login.example.test/");
  await unlock(popup, username);
  await expect(popup.locator("[name=list-title]")).toHaveText(
    "No logins saved for login.example.test",
  );

  // save what was typed into the page
  await site.fill("input[name=user]", "alice@example.com");
  await site.fill("input[name=pass]", "first secret");
  await popup.click("summary:has-text('Save a login')");
  await popup.click("button[name=read-page]");
  await expect(popup.locator("input[name=save-username]")).toHaveValue(
    "alice@example.com",
  );
  await expect(popup.locator("select[name=save-table]")).toHaveValue("new");
  await popup.click("button[name=save]");
  await expect(popup.locator("#status")).toHaveText(
    "Saved the login for login.example.test.",
  );
  const login = popup.locator(".ext-login");
  await expect(login).toHaveCount(1);
  await expect(login).toContainText("alice@example.com");

  // filling it in
  await site.reload();
  await login.locator("button:has-text('Fill')").click();
  await expect(popup.locator("#status")).toHaveText(
    "Filled the username and password.",
  );
  await expect(site.locator("input[name=user]")).toHaveValue(
    "alice@example.com",
  );
  await expect(site.locator("input[name=pass]")).toHaveValue("first secret");

  // saving a new password for the same username changes that login
  await site.fill("input[name=pass]", "second secret");
  await popup.click("button[name=read-page]");
  await expect(popup.locator("select[name=save-table] option")).toHaveCount(2);
  await popup.click("button[name=save]");
  await expect(popup.locator("#status")).toHaveText(
    "Changed the password for alice@example.com.",
  );
  await expect(login).toHaveCount(1);

  // the web app has it
  await app.goto(`${SERVER}/?server_pass=test`);
  await app.fill("#login-username", username);
  await app.fill("#login-password", PASSWORD);
  await app.click("#login input[name='submit']");
  await expect(app.locator(".pm-card-name")).toHaveText(["Logins"]);

  // a popup opened later stays unlocked, and another site gets no Fill
  // button even when searching finds the login
  await popup.close();
  const other = await context.newPage();
  await other.goto("https://login.example-phish.test/");
  popup = await openPopup(context, worker, "https://login.example-phish.test/");
  await expect(popup.locator("#unlocked")).toBeVisible();
  await expect(popup.locator("[name=list-title]")).toHaveText(
    "No logins saved for login.example-phish.test",
  );
  await popup.fill("input[name=search]", "alice");
  await expect(popup.locator(".ext-login")).toHaveCount(1);
  await expect(popup.locator(".ext-login button:has-text('Fill')")).toHaveCount(
    0,
  );
  await expect(
    popup.locator(".ext-login button:has-text('Copy password')"),
  ).toBeVisible();

  // locking forgets the session
  await popup.click("button[name=lock]");
  await expect(popup.locator("#locked")).toBeVisible();
  await expect(popup.locator("input[name=username]")).toHaveValue(username);
  expect(
    await worker.evaluate(() => chrome.storage.session.get("session")),
  ).toEqual({});
});

test("generates a password and fills it into a sign-up form", async ({
  context,
  worker,
}) => {
  const username = uniqueUsername();
  await register(await context.newPage(), username);
  await context.route("https://signup.example.test/**", (route) =>
    route.fulfill({
      contentType: "text/html",
      body: `<!doctype html><form>
        <input type="email" name="email">
        <input type="password" name="new" autocomplete="new-password">
        <input type="password" name="confirm" autocomplete="new-password">
      </form>`,
    }),
  );
  const site = await context.newPage();
  await site.goto("https://signup.example.test/");
  const popup = await openPopup(
    context,
    worker,
    "https://signup.example.test/",
  );
  await unlock(popup, username);

  await popup.click("summary:has-text('Save a login')");
  await popup.fill("input[name=save-username]", "bob@example.com");
  await popup.click("button:has-text('Generate')");
  const password = await popup
    .locator("input[name=save-password]")
    .inputValue();
  expect(password).toHaveLength(20);
  await popup.click("button:has-text('Fill into page')");
  await expect(site.locator("input[name=email]")).toHaveValue(
    "bob@example.com",
  );
  await expect(site.locator("input[name=new]")).toHaveValue(password);
  await expect(site.locator("input[name=confirm]")).toHaveValue(password);

  await popup.click("button[name=save]");
  await expect(popup.locator("#status")).toHaveText(
    "Saved the login for signup.example.test.",
  );
  await popup.click(".ext-login button:has-text('Copy password')");
  await expect(popup.locator("#status")).toHaveText("Password copied.");
});

test("fills MFA codes, and logins from shared vaults", async ({
  context,
  worker,
}) => {
  const RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const username = uniqueUsername();
  const app = await context.newPage();
  await register(app, username);
  await app.fill("#login-username", username);
  await app.fill("#login-password", PASSWORD);
  await app.click("#login input[name='submit']");
  await expect(app.locator("#content")).toBeVisible();
  const savedOwn = () =>
    app.waitForResponse(
      (r) =>
        r.url().includes("/pass-table?") &&
        r.request().method() === "PUT" &&
        r.status() === 200,
    );
  const savedShared = () =>
    app.waitForResponse(
      (r) =>
        /\/shared-vaults\/[0-9a-f]+\/version/.test(r.url()) &&
        r.request().method() === "PUT" &&
        r.status() === 200,
    );

  // a login with an MFA key in the user's own vault, imported
  await app.click("details[name='import-export'] summary");
  await app.setInputFiles("input[name='import-file']", {
    name: "logins.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(
      `name,url,username,password,totp\nBank,https://bank.example.test,alice,bank secret,${RFC_KEY}\n`,
    ),
  });
  let done = savedOwn();
  await app.click("button[name='confirm-import']");
  await done;

  // and one in a shared vault
  done = savedOwn();
  await app.click("#shared-vaults button[name='setup-sharing']");
  await done;
  await app.fill("#shared-vaults input[name='shared-name']", "Family");
  await app.click("#shared-vaults button:has-text('Create shared vault')");
  const card = app.locator("#shared-vaults .pm-shared-vault");
  done = savedShared();
  await card.locator("button:has-text('Add Table')").click();
  await done;
  for (const [label, type] of [
    ["Site", "link"],
    ["Username", "textarea"],
  ]) {
    done = savedShared();
    await card.locator(".pm-card-header button:has-text('Add Column')").click();
    await app.fill(".pm-modal input[type='text']", label);
    await app.locator(".pm-modal select").selectOption(type);
    await app.click(".pm-modal button:has-text('Add Column')");
    await done;
  }
  done = savedShared();
  await card.locator(".pm-card-header button:has-text('Add Row')").click();
  await done;
  const cells = card.locator("td.pm-td-data");
  done = savedShared();
  await cells.nth(0).focus();
  await cells.nth(0).press("Enter");
  await cells.nth(0).locator("input").first().fill("https://wifi.example.test");
  await cells.nth(0).locator("input").first().press("Enter");
  await done;
  done = savedShared();
  await cells.nth(1).focus();
  await cells.nth(1).press("Enter");
  await cells.nth(1).locator("textarea").fill("router-admin");
  await cells.nth(1).locator("textarea").press("Control+Enter");
  await done;

  await serveSites(context);
  const bank = await context.newPage();
  await bank.goto("https://bank.example.test/");
  let popup = await openPopup(context, worker, "https://bank.example.test/");
  await unlock(popup, username);
  const login = popup.locator(".ext-login");
  await expect(login).toHaveCount(1);
  const code = await login.locator(".ext-code").textContent();
  expect(code).toMatch(/^\d{3} \d{3}$/);
  await login.locator("button:has-text('Fill code')").click();
  // the made-up page has no code field
  await expect(popup.locator("#status")).toHaveText(
    "No field to fill was found on this page.",
  );
  await login.locator("button:has-text('Fill')").first().click();
  await expect(bank.locator("input[name=pass]")).toHaveValue("bank secret");

  // the shared vault's login, checked and kept with the session
  const wifi = await context.newPage();
  await wifi.goto("https://wifi.example.test/");
  popup = await openPopup(context, worker, "https://wifi.example.test/");
  const shared = popup.locator(".ext-login");
  await expect(shared).toHaveCount(1);
  await expect(shared.locator(".ext-badge")).toHaveText("Family");
  await shared.locator("button:has-text('Fill')").click();
  await expect(wifi.locator("input[name=user]")).toHaveValue("router-admin");
});
