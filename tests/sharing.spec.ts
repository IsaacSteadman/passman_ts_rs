import { test, expect, type Page } from "@playwright/test";

/**
 * End-to-end tests of shared vaults: two users set up sharing, one creates a
 * shared vault and adds the other, and both edit it.
 */
const START = "/?server_pass=test";
const PASSWORD = "correct horse";

function uniqueUsername(): string {
  return `u${Date.now()}${Math.floor(Math.random() * 1e6)}`;
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

async function login(page: Page, username: string): Promise<void> {
  await page.goto(START);
  await page.waitForLoadState("networkidle");
  await page.fill("#login-username", username);
  await page.fill("#login-password", PASSWORD);
  await page.click("#login input[name='submit']");
  await expect(page.locator("#content")).toBeVisible();
}

/** Registers, logs in and sets up sharing; returns the shown fingerprint. */
async function newSharingUser(page: Page, username: string): Promise<string> {
  await register(page, username);
  await login(page, username);
  await page.click("#shared-vaults button[name='setup-sharing']");
  const line = page.locator("#shared-vaults [name='sharing-fingerprint']");
  await expect(line).toContainText("fingerprint:");
  return (await line.textContent())!.replace(/^.*fingerprint: /, "");
}

/** Runs `action` and waits for the shared vault save it triggers. */
async function savedShared(
  page: Page,
  action: () => Promise<void>,
  status = 200,
): Promise<void> {
  const done = page.waitForResponse(
    (r) =>
      /\/shared-vaults\/[0-9a-f]+\/data/.test(r.url()) &&
      r.request().method() === "PUT" &&
      r.status() === status,
  );
  await action();
  await done;
}

const vaultCard = (page: Page, name: string) =>
  page.locator("#shared-vaults .pm-shared-vault", {
    has: page.locator(".pm-shared-name", { hasText: name }),
  });

async function renameTable(
  page: Page,
  card: string,
  index: number,
  name: string,
) {
  const nameEl = vaultCard(page, card).locator(".pm-card-name").nth(index);
  await nameEl.fill(name);
  await nameEl.press("Enter");
}

test.describe("Shared vaults", () => {
  test("a vault shared with another user can be opened and edited by both", async ({
    browser,
  }) => {
    const aliceName = uniqueUsername();
    const bobName = uniqueUsername();
    const alice = await (await browser.newContext()).newPage();
    const bob = await (await browser.newContext()).newPage();
    await newSharingUser(alice, aliceName);
    const bobFingerprint = await newSharingUser(bob, bobName);

    // the sharing key is kept in the user's own vault
    await login(bob, bobName);
    await expect(
      bob.locator("#shared-vaults [name='sharing-fingerprint']"),
    ).toContainText(bobFingerprint);

    // alice creates a vault and adds a table to it
    await alice.fill("#shared-vaults input[name='shared-name']", "Family");
    await alice.click("#shared-vaults button:has-text('Create shared vault')");
    const card = vaultCard(alice, "Family");
    await expect(card).toHaveAttribute("open", "");
    await expect(card.locator(".pm-shared-meta").first()).toHaveText(
      "Owner · 1 member",
    );
    await savedShared(alice, () =>
      card.locator("button:has-text('Add Table')").click(),
    );
    await savedShared(alice, () => renameTable(alice, "Family", 0, "Wifi"));
    // the personal vault is separate
    await expect(alice.locator("div[name='data'] .pm-card-name")).toHaveCount(
      0,
    );

    // and adds bob after checking his fingerprint
    await card.locator("input[name='member-username']").fill(bobName);
    await card.locator("button:has-text('Add member')").click();
    await expect(card.locator(".pm-add-member-confirm")).toContainText(
      bobFingerprint,
    );
    await card.locator(`button:has-text('Add ${bobName} as Editor')`).click();
    await expect(card.locator(".pm-shared-meta").first()).toHaveText(
      "Owner · 2 members",
    );

    // bob sees it after logging in again
    await login(bob, bobName);
    const bobCard = vaultCard(bob, "Family");
    await expect(bobCard.locator(".pm-shared-meta").first()).toHaveText(
      "Editor · 2 members",
    );
    await bobCard.locator("summary").click();
    await expect(bobCard.locator(".pm-card-name")).toHaveText(["Wifi"]);

    // bob's change is merged into alice's stale session when she saves
    await savedShared(bob, () =>
      bobCard.locator("button:has-text('Add Table')").click(),
    );
    await savedShared(bob, () => renameTable(bob, "Family", 1, "From Bob"));
    await savedShared(
      alice,
      () => renameTable(alice, "Family", 0, "Home Wifi"),
      412,
    );
    await expect(card.locator(".pm-card-name")).toHaveText([
      "Home Wifi",
      "From Bob",
    ]);

    // an editor can leave but not manage members
    await expect(bobCard.locator("input[name='member-username']")).toHaveCount(
      0,
    );

    // once removed, bob no longer sees the vault
    alice.once("dialog", (dialog) => dialog.accept());
    await card
      .locator(`.pm-member-list li[data-username='${bobName}'] button`)
      .click();
    await expect(card.locator(".pm-shared-meta").first()).toHaveText(
      "Owner · 1 member",
    );
    await login(bob, bobName);
    await expect(bob.locator("#shared-vaults .pm-empty-note")).toContainText(
      "No shared vaults yet",
    );
  });

  test("members can only be added once they've set up sharing", async ({
    page,
  }) => {
    const owner = uniqueUsername();
    const other = uniqueUsername();
    await register(page, other);
    await newSharingUser(page, owner);
    await page.fill("#shared-vaults input[name='shared-name']", "Work");
    await page.click("#shared-vaults button:has-text('Create shared vault')");
    const card = vaultCard(page, "Work");
    await card.locator("input[name='member-username']").fill(other);
    await card.locator("button:has-text('Add member')").click();
    await expect(card.locator(".pm-add-member-confirm")).toContainText(
      "has set up sharing",
    );

    // the owner deletes it
    page.once("dialog", (dialog) => dialog.accept());
    await card.locator("button:has-text('Delete shared vault')").click();
    await expect(card).toHaveCount(0);
  });
});
