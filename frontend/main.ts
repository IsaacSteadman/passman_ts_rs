import { initWasm, encryptBlob } from "./passman_crypto_glue";
import {
  initLoginArea,
  credentialHeaders,
  deriveUserKeys,
  readServerAccessParams,
  type LoginResult,
} from "./loginArea";
import { initContentArea } from "./contentArea";
import { initPassgenPanel } from "./passgenPanel";

document.addEventListener("DOMContentLoaded", async () => {
  // Prefill server access params from URL query params if present
  const urlParams = new URLSearchParams(window.location.search);
  const urlServerPass = urlParams.get("server_pass");
  const urlServerNs = urlParams.get("server_ns");
  const serverAccessForm = document.querySelector(
    "form#server-access",
  ) as HTMLFormElement | null;
  if (urlServerPass != null) {
    const inp = serverAccessForm?.querySelector(
      "input[name='server_pass']",
    ) as HTMLInputElement | null;
    if (inp) inp.value = urlServerPass;
  }
  if (urlServerNs != null) {
    const inp = serverAccessForm?.querySelector(
      "input[name='server_ns']",
    ) as HTMLInputElement | null;
    if (inp) inp.value = urlServerNs;
  }

  await initWasm();

  const loginDiv = document.querySelector("div#login") as HTMLDivElement;
  const registerDiv = document.querySelector("div#register") as HTMLDivElement;
  const contentDiv = document.querySelector("div#content") as HTMLDivElement;
  const errorPanel =
    (document.querySelector("p#error-panel") as HTMLElement | null) ??
    document.createElement("p");

  // The auth wrap wraps the entire pre-login card; hide it as a unit on login.
  const authWrap = document.querySelector(
    ".pm-auth-wrap",
  ) as HTMLElement | null;

  const contentHandle = initContentArea(contentDiv, () => {
    // onLogout — restore the auth card and ensure the Login tab is active
    contentDiv.style.display = "none";
    loginDiv.style.display = "";
    if (authWrap) authWrap.style.display = "";
  });

  initPassgenPanel(() => contentHandle.getCurrentData()?.tables ?? null);

  initLoginArea(errorPanel, (result: LoginResult) => {
    if (authWrap) authWrap.style.display = "none";
    contentHandle.show(result);
  });

  // --- Register form ---
  const registerForm = registerDiv.querySelector("form")!;
  const regUsernameInput = registerForm.querySelector(
    "input[name='username']",
  ) as HTMLInputElement;
  const regPasswordInput = registerForm.querySelector(
    "input[name='new_pass']",
  ) as HTMLInputElement;
  const regConfirmInput = registerForm.querySelector(
    "input[name='confirm_new_pass']",
  ) as HTMLInputElement;
  const regShowCheckbox = registerForm.querySelector(
    "input[name='show-new-pass']",
  ) as HTMLInputElement;
  const regSubmitButton = registerForm.querySelector(
    "input[name='submit']",
  ) as HTMLInputElement;

  regShowCheckbox.addEventListener("change", () => {
    const type = regShowCheckbox.checked ? "text" : "password";
    regPasswordInput.type = type;
    regConfirmInput.type = type;
  });

  regSubmitButton.addEventListener("click", async (event) => {
    event.preventDefault();
    errorPanel.textContent = "";

    const username = regUsernameInput.value;
    const password = regPasswordInput.value;
    const confirm = regConfirmInput.value;

    if (password !== confirm) {
      errorPanel.textContent = "Passwords do not match.";
      return;
    }
    if (!password) {
      errorPanel.textContent = "Password cannot be empty.";
      return;
    }

    const { serverPass, serverNs } = readServerAccessParams();

    let authKeyB64: string;
    let encryptionKey: Uint8Array;
    try {
      ({ authKeyB64, encryptionKey } = await deriveUserKeys(
        username,
        password,
      ));
    } catch (e) {
      errorPanel.textContent = `Key derivation failed: ${e}`;
      return;
    }

    const emptyTable = new TextEncoder().encode(
      JSON.stringify({ tables: [], history: [] }),
    );
    const blob = encryptBlob(encryptionKey, emptyTable);

    const url = new URL("/pass-table", window.location.origin);
    url.searchParams.set("username", username);
    if (serverNs != null) url.searchParams.set("server_ns", serverNs);

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method: "POST",
        headers: {
          ...credentialHeaders(authKeyB64, serverPass),
          "Content-Type": "application/octet-stream",
          "Content-Length": String(blob.byteLength),
        },
        body: blob,
      });
    } catch (e) {
      errorPanel.textContent = `Network error: ${e}`;
      return;
    }

    if (!response.ok) {
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = await response.text();
      }
      errorPanel.textContent = `Registration failed (${response.status}): ${JSON.stringify(body)}`;
      return;
    }

    // Switch back to login with a success hint
    errorPanel.textContent = "Account created — please log in.";
    registerDiv.style.display = "none";
    loginDiv.style.display = "";
  });
});
