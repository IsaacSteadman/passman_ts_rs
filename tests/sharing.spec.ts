import { test, expect, type Browser, type Page } from "@playwright/test";

/**
 * End-to-end tests of shared vaults: verifying each other (QR codes and
 * safety numbers), sharing, permissions, member changes (which start a new
 * epoch with a new key), leaving, and working offline. Each test registers
 * its own users.
 */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

function uniqueUsername(): string {
  return `s${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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

/** Registers and logs in a new user with sharing set up. */
async function sharingUser(
  browser: Browser,
  { remember = false } = {},
): Promise<{ page: Page; name: string }> {
  const name = uniqueUsername();
  const page = await (await browser.newContext()).newPage();
  await register(page, name);
  await login(page, name, { remember });
  const published = page.waitForResponse(
    (r) => r.url().includes("/identity?") && r.request().method() === "PUT",
  );
  await page.click("#shared-vaults button[name='setup-sharing']");
  await published;
  await expect(
    page.locator("#shared-vaults [name='sharing-fingerprint']"),
  ).toContainText("fingerprint:");
  return { page, name };
}

const modal = (page: Page) => page.locator(".pm-verify-modal");

async function openVerify(page: Page, name: string): Promise<void> {
  await page.fill("#shared-vaults input[name='verify-username']", name);
  await page.click("#shared-vaults button:has-text('Verify someone')");
  await expect(modal(page)).toBeVisible();
}

/** `scanner` verifies `shower` by scanning (a photo of) their QR code. */
async function verifyByQr(
  scanner: Page,
  shower: { page: Page; name: string },
): Promise<void> {
  await shower.page.click("#shared-vaults button[name='show-my-code']");
  const png = await modal(shower.page).locator(".pm-qr").screenshot();
  await modal(shower.page).locator("button:has-text('Close')").click();

  await openVerify(scanner, shower.name);
  await modal(scanner)
    .locator("input[name='qr-photo']")
    .setInputFiles({ name: "code.png", mimeType: "image/png", buffer: png });
  await expect(modal(scanner).locator(".pm-verify-result")).toContainText(
    `${shower.name} is verified`,
  );
  await modal(scanner).locator("button:has-text('Close')").click();
}

/** The safety number `page` shows for verifying `name`. */
async function safetyNumber(page: Page, name: string): Promise<string> {
  await openVerify(page, name);
  return (await modal(page).locator(".pm-safety-number").textContent())!;
}

const vaultCard = (page: Page, name: string) =>
  page.locator("#shared-vaults .pm-shared-vault", {
    has: page.locator(".pm-shared-name", { hasText: name }),
  });

/** Runs `action` and waits for the shared vault save it triggers. */
async function savedShared(
  page: Page,
  action: () => Promise<void>,
  status = 200,
): Promise<void> {
  const done = page.waitForResponse(
    (r) =>
      /\/shared-vaults\/[0-9a-f]+\/version/.test(r.url()) &&
      r.request().method() === "PUT" &&
      r.status() === status,
  );
  await action();
  await done;
}

/** Applies the member changes made in `card`, starting a new epoch. */
async function applyMembers(page: Page, vault: string): Promise<void> {
  const done = page.waitForResponse(
    (r) =>
      /\/shared-vaults\/[0-9a-f]+\/records/.test(r.url()) &&
      r.request().method() === "POST" &&
      r.status() === 200,
  );
  await vaultCard(page, vault).locator("button[name='apply-members']").click();
  await done;
}

async function renameTable(
  page: Page,
  vault: string,
  index: number,
  name: string,
) {
  const nameEl = vaultCard(page, vault).locator(".pm-card-name").nth(index);
  await nameEl.fill(name);
  await nameEl.press("Enter");
}

async function createVault(page: Page, name: string): Promise<void> {
  await page.fill("#shared-vaults input[name='shared-name']", name);
  await page.click("#shared-vaults button:has-text('Create shared vault')");
  await expect(vaultCard(page, name)).toHaveAttribute("open", "");
}

const member = (page: Page, vault: string, name: string) =>
  vaultCard(page, vault).locator(`.pm-member-list li[data-username='${name}']`);

test.describe("Shared vaults", () => {
  test("verified members share a vault, with permissions and new keys on member changes", async ({
    browser,
  }) => {
    const alice = await sharingUser(browser);
    const bob = await sharingUser(browser);

    // alice verifies bob in person (QR); bob verifies alice on a call
    await verifyByQr(alice.page, bob);
    const bobSees = await safetyNumber(bob.page, alice.name);
    const aliceSees = await safetyNumber(alice.page, bob.name);
    expect(bobSees).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(aliceSees).toBe(bobSees);
    await modal(alice.page).locator("button:has-text('Close')").click();
    await modal(bob.page).locator("button:has-text('It matches')").click();
    await expect(modal(bob.page).locator(".pm-verify-result")).toContainText(
      "is verified",
    );
    await modal(bob.page).locator("button:has-text('Close')").click();

    // alice creates a vault with a table, then adds bob
    await createVault(alice.page, "Family");
    const card = vaultCard(alice.page, "Family");
    await savedShared(alice.page, () =>
      card.locator("button:has-text('Add Table')").click(),
    );
    await savedShared(alice.page, () =>
      renameTable(alice.page, "Family", 0, "Wifi"),
    );
    // the personal vault is separate
    await expect(
      alice.page.locator("div[name='data'] .pm-card-name"),
    ).toHaveCount(0);
    await card.locator("select[name='add-member']").selectOption(bob.name);
    await card.locator(".pm-add-member button:has-text('Add')").click();
    await applyMembers(alice.page, "Family");
    await expect(member(alice.page, "Family", bob.name)).toContainText(
      "✓ verified by you",
    );

    // bob sees it after logging in again, and can edit it
    await login(bob.page, bob.name);
    const bobCard = vaultCard(bob.page, "Family");
    await expect(
      bobCard.locator(":scope > summary .pm-shared-meta"),
    ).toContainText("Can edit · 2 members");
    await bobCard.locator(":scope > summary").click();
    await expect(bobCard.locator(".pm-card-name")).toHaveText(["Wifi"]);
    await expect(member(bob.page, "Family", alice.name)).toContainText(
      "✓ verified by you",
    );
    await expect(bobCard.locator(".pm-unverified-managers")).toHaveCount(0);
    await savedShared(bob.page, () =>
      bobCard.locator("button:has-text('Add Table')").click(),
    );
    await savedShared(bob.page, () =>
      renameTable(bob.page, "Family", 1, "From Bob"),
    );

    // bob only sees the history from when he joined
    await bobCard.locator(".pm-history-details summary").click();
    await expect(bobCard.locator(".pm-history-list")).toContainText(
      'Renamed table "New Table" → "From Bob"',
    );
    await expect(bobCard.locator(".pm-history-list")).not.toContainText(
      '"New Table" → "Wifi"',
    );
    await card.locator(".pm-history-details summary").click();
    await expect(card.locator(".pm-history-list")).toContainText(
      '"New Table" → "Wifi"',
    );

    // alice's stale session merges bob's change when she saves
    await savedShared(
      alice.page,
      () => renameTable(alice.page, "Family", 0, "Home Wifi"),
      412,
    );
    await expect(card.locator(".pm-card-name")).toHaveText([
      "Home Wifi",
      "From Bob",
    ]);

    // alice makes bob read-only
    await member(alice.page, "Family", bob.name)
      .locator("label:has-text('can edit') input")
      .uncheck();
    await applyMembers(alice.page, "Family");
    await login(bob.page, bob.name);
    await expect(
      bobCard.locator(":scope > summary .pm-shared-meta"),
    ).toContainText("Read only");
    await bobCard.locator(":scope > summary").click();
    await expect(bobCard.locator(".pm-card-name")).toHaveText([
      "Home Wifi",
      "From Bob",
    ]);
    await expect(bobCard.locator("button:has-text('Add Table')")).toHaveCount(
      0,
    );
    await expect(bobCard.locator(".pm-add-member")).toHaveCount(0);

    // and then removes him
    await member(alice.page, "Family", bob.name)
      .locator("button:has-text('Remove')")
      .click();
    await applyMembers(alice.page, "Family");
    await login(bob.page, bob.name);
    await expect(
      bob.page.locator("#shared-vaults .pm-empty-note"),
    ).toContainText("No shared vaults yet");
  });

  test("only verified people can be added, and members who leave are removed by a manager", async ({
    browser,
  }) => {
    const alice = await sharingUser(browser);
    const carol = await sharingUser(browser);
    await createVault(alice.page, "Work");
    const card = vaultCard(alice.page, "Work");
    await expect(card.locator(".pm-add-member")).toContainText(
      "verify them first",
    );

    await safetyNumber(alice.page, carol.name);
    await modal(alice.page).locator("button:has-text('It matches')").click();
    await modal(alice.page).locator("button:has-text('Close')").click();
    await card.locator("select[name='add-member']").selectOption(carol.name);
    await card.locator(".pm-add-member button:has-text('Add')").click();
    await applyMembers(alice.page, "Work");

    // carol leaves
    await login(carol.page, carol.name);
    const carolCard = vaultCard(carol.page, "Work");
    await carolCard.locator(":scope > summary").click();
    // carol hasn't verified alice, who manages it
    await expect(carolCard.locator(".pm-unverified-managers")).toContainText(
      `managed by ${alice.name}, whose identity you haven't verified`,
    );
    carol.page.once("dialog", (dialog) => dialog.accept());
    await carolCard.locator("button:has-text('Leave')").click();
    await expect(carolCard).toHaveCount(0);

    // alice's browser removes her (with a new key) when it next loads
    const removed = alice.page.waitForResponse(
      (r) => /\/records/.test(r.url()) && r.request().method() === "POST",
    );
    await login(alice.page, alice.name);
    expect((await removed).status()).toBe(200);
    await vaultCard(alice.page, "Work").locator(":scope > summary").click();
    await expect(member(alice.page, "Work", carol.name)).toHaveCount(0);

    // deleting the vault
    alice.page.once("dialog", (dialog) => dialog.accept());
    await vaultCard(alice.page, "Work")
      .locator("button:has-text('Delete shared vault')")
      .click();
    await expect(vaultCard(alice.page, "Work")).toHaveCount(0);
  });

  test("a remembered account's shared vaults can be edited offline", async ({
    browser,
  }) => {
    const alice = await sharingUser(browser, { remember: true });
    const page = alice.page;
    await page.evaluate(() => navigator.serviceWorker.ready);
    await page.waitForFunction(
      () => navigator.serviceWorker.controller != null,
    );
    await createVault(page, "Trip");
    await savedShared(page, () =>
      vaultCard(page, "Trip").locator("button:has-text('Add Table')").click(),
    );
    await page.click("button[name='logout']");

    const unlock = async () => {
      await page.click(`.pm-account:has-text('${alice.name}')`);
      await page.fill("#unlock-password", PASSWORD);
      await page.click("#remembered input[name='unlock']");
    };
    // offline: the vault is opened from the device and can be changed
    await page.context().setOffline(true);
    await page.reload();
    await unlock();
    const card = vaultCard(page, "Trip");
    await card.locator(":scope > summary").click();
    await renameTable(page, "Trip", 0, "Edited Offline");
    await expect(card.locator(".pm-chg-pass-status").first()).toContainText(
      "Offline — changes are kept on this device",
    );

    // the change survives closing the app
    await page.reload();
    await unlock();
    await vaultCard(page, "Trip").locator(":scope > summary").click();
    await expect(vaultCard(page, "Trip").locator(".pm-card-name")).toHaveText([
      "Edited Offline",
    ]);

    // back online: it's saved
    await savedShared(page, () => page.context().setOffline(false));
    const other = await (await browser.newContext()).newPage();
    await login(other, alice.name);
    await vaultCard(other, "Trip").locator(":scope > summary").click();
    await expect(vaultCard(other, "Trip").locator(".pm-card-name")).toHaveText([
      "Edited Offline",
    ]);
  });
});
