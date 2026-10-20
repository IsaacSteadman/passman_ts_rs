// Lists the accounts remembered on this device on the login card, and unlocks
// them. Unlocking reads the vault cached on the device, so it works offline.

import {
  forgetAccount,
  listAccounts,
  type RememberedAccount,
} from "./deviceStore";
import { unlockWithPassword, type LoginResult } from "./loginArea";

export interface LockScreenHandle {
  /** Re-reads the remembered accounts (e.g. after logging out). */
  refresh(): Promise<void>;
}

export function initLockScreen(
  errorPanel: HTMLElement,
  onUnlock: (result: LoginResult) => void,
): LockScreenHandle {
  const authCard = document.querySelector(".pm-auth-card") as HTMLElement;
  const rememberedDiv = document.querySelector(
    "div#remembered",
  ) as HTMLDivElement;
  const list = rememberedDiv.querySelector(
    ".pm-account-list",
  ) as HTMLUListElement;
  const form = rememberedDiv.querySelector("form.pm-unlock") as HTMLFormElement;
  const accountLabel = form.querySelector(
    ".pm-unlock-account",
  ) as HTMLParagraphElement;
  const usernameInput = form.querySelector(
    "input[name='username']",
  ) as HTMLInputElement;
  const passwordInput = form.querySelector(
    "input[name='password']",
  ) as HTMLInputElement;
  const unlockButton = form.querySelector(
    "input[name='unlock']",
  ) as HTMLInputElement;
  const backButton = form.querySelector(
    "button[name='back']",
  ) as HTMLButtonElement;
  const forgetButton = form.querySelector(
    "button[name='forget']",
  ) as HTMLButtonElement;

  let selected: RememberedAccount | null = null;

  function describe(account: RememberedAccount): string {
    return account.serverNs
      ? `${account.username} (${account.serverNs})`
      : account.username;
  }

  function select(account: RememberedAccount | null): void {
    selected = account;
    errorPanel.textContent = "";
    passwordInput.value = "";
    authCard.classList.toggle("pm-unlocking", account != null);
    if (account == null) return;
    accountLabel.textContent = `Unlock ${describe(account)}`;
    usernameInput.value = account.username;
    passwordInput.focus();
  }

  async function refresh(): Promise<void> {
    let accounts: RememberedAccount[];
    try {
      accounts = await listAccounts();
    } catch (e) {
      // e.g. storage disabled: only the normal login is available
      console.warn("Couldn't read remembered accounts", e);
      accounts = [];
    }
    list.innerHTML = "";
    for (const account of accounts) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "pm-account";
      const name = document.createElement("span");
      name.className = "pm-account-name";
      name.textContent = account.username;
      button.append(name);
      if (account.serverNs) {
        const ns = document.createElement("span");
        ns.className = "pm-account-ns";
        ns.textContent = account.serverNs;
        button.append(ns);
      }
      button.addEventListener("click", () => select(account));
      item.append(button);
      list.append(item);
    }
    rememberedDiv.style.display = accounts.length > 0 ? "" : "none";
    select(null);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const account = selected;
    if (account == null) return;
    errorPanel.textContent = "Unlocking…";
    unlockButton.disabled = true;
    try {
      const result = await unlockWithPassword(
        account.username,
        account.serverNs,
        account.serverPass,
        passwordInput.value,
        true,
      );
      if (typeof result === "string") {
        errorPanel.textContent = result;
        return;
      }
      select(null);
      onUnlock(result);
    } finally {
      unlockButton.disabled = false;
    }
  });

  backButton.addEventListener("click", () => select(null));

  forgetButton.addEventListener("click", async () => {
    const account = selected;
    if (
      account == null ||
      !window.confirm(
        `Remove ${describe(account)} from this device? Changes that haven't been saved to the server yet will be lost. The account itself isn't affected.`,
      )
    )
      return;
    try {
      await forgetAccount(account.id);
    } catch (e) {
      errorPanel.textContent = `Couldn't remove the account: ${e}`;
      return;
    }
    await refresh();
  });

  void refresh();
  return { refresh };
}
