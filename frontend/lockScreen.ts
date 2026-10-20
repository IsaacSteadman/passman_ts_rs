// Lists the accounts remembered on this device on the login card, and unlocks
// them with biometrics or the password. Unlocking reads the vault cached on
// the device, so it works offline.

import {
  forgetAccount,
  listAccounts,
  type RememberedAccount,
} from "./deviceStore";
import {
  keyProtector,
  unlockErrorMessage,
  type ProtectionStatus,
  type UnlockSecrets,
} from "./keyProtector";
import {
  unlockWithKeys,
  unlockWithPassword,
  type LoginResult,
} from "./loginArea";

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
  const biometricDiv = form.querySelector(
    ".pm-biometric-unlock",
  ) as HTMLDivElement;
  const biometricButton = biometricDiv.querySelector(
    "button[name='biometric']",
  ) as HTMLButtonElement;

  let selected: RememberedAccount | null = null;
  // biometric unlock's state per account, read when the list is shown so the
  // prompt can start straight from a tap
  let protection = new Map<string, ProtectionStatus | null>();

  function canUseBiometrics(account: RememberedAccount): boolean {
    return protection.get(account.id)?.current === true;
  }

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
    biometricDiv.style.display = canUseBiometrics(account) ? "" : "none";
    if (!canUseBiometrics(account)) passwordInput.focus();
  }

  async function unlockWithBiometrics(account: RememberedAccount) {
    errorPanel.textContent = "Waiting for biometrics…";
    biometricButton.disabled = true;
    try {
      let keys: UnlockSecrets;
      try {
        keys = await keyProtector.unlock(account.id);
      } catch (e) {
        errorPanel.textContent = unlockErrorMessage(e);
        return;
      }
      errorPanel.textContent = "Unlocking…";
      const result = await unlockWithKeys(
        account.username,
        account.serverNs,
        account.serverPass,
        keys,
        true,
      );
      if (typeof result === "string") {
        errorPanel.textContent = `${result} Unlock with the password instead.`;
        return;
      }
      select(null);
      onUnlock(result);
    } finally {
      biometricButton.disabled = false;
    }
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
    protection = new Map(
      await Promise.all(
        accounts.map(
          async (account) =>
            [
              account.id,
              await keyProtector.status(account.id).catch(() => null),
            ] as const,
        ),
      ),
    );
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
      button.addEventListener("click", () => {
        select(account);
        if (canUseBiometrics(account)) void unlockWithBiometrics(account);
      });
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

  biometricButton.addEventListener("click", () => {
    if (selected) void unlockWithBiometrics(selected);
  });

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
      await keyProtector.remove(account.id);
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
