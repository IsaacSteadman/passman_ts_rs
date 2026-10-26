// Functions run in the page of the current tab (scripting.executeScript),
// only when the user asks: they're serialized and run there on their own, so
// each must not use anything from outside its body.

export interface FillRequest {
  /** The page's origin when the user chose the login; nothing is filled if
   *  the tab went to another one since. */
  origin: string;
  username: string | null;
  password: string | null;
  /** A one-time code. */
  code: string | null;
  /** Fills every password field of the form, as sign-up and change-password
   *  forms ask for a new password twice. */
  newPassword: boolean;
}

export interface FillResult {
  error: string | null;
  filled: ("username" | "password" | "code")[];
}

export function fillPage(request: FillRequest): FillResult {
  if (location.origin !== request.origin)
    return { error: "The page changed. Try again.", filled: [] };

  const usable = (input: HTMLInputElement) =>
    !input.disabled &&
    !input.readOnly &&
    input.type !== "hidden" &&
    input.getClientRects().length > 0 &&
    getComputedStyle(input).visibility !== "hidden";
  const inputs = (root: ParentNode, selector: string) =>
    Array.from(root.querySelectorAll<HTMLInputElement>(selector)).filter(
      usable,
    );
  const TEXT = "input:not([type]), input[type=text], input[type=email]";
  const named = (input: HTMLInputElement, pattern: RegExp) =>
    pattern.test(
      `${input.name} ${input.id} ${input.autocomplete} ${input.placeholder}`,
    );
  // React and similar keep their own copy of the value, updated by these
  // events; the native setter makes sure they see the change
  const setValue = (input: HTMLInputElement, value: string) => {
    input.focus();
    const setter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const filled: FillResult["filled"] = [];
  const passwords = inputs(document, "input[type=password]");
  const first =
    passwords.find((p) => p.autocomplete === "current-password") ??
    passwords[0];

  if (request.username != null) {
    let field: HTMLInputElement | undefined;
    if (first) {
      // the text field before the password field, in its form
      const before = inputs(first.form ?? document, TEXT).filter(
        (input) =>
          input.compareDocumentPosition(first) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      );
      field =
        before.find((input) => /username|email/.test(input.autocomplete)) ??
        before[before.length - 1];
    } else {
      // a page asking for the username first
      const text = inputs(document, TEXT);
      field =
        text.find((input) => /username|email/.test(input.autocomplete)) ??
        text.find((input) => input.type === "email") ??
        text.find((input) => named(input, /user|email|login|account/i));
    }
    if (field) {
      setValue(field, request.username);
      filled.push("username");
    }
  }

  if (request.password != null && first) {
    const targets = request.newPassword
      ? passwords.filter(
          (p) => p.form === first.form && p.autocomplete !== "current-password",
        )
      : [first];
    for (const field of targets.length > 0 ? targets : [first])
      setValue(field, request.password);
    filled.push("password");
  }

  if (request.code != null) {
    const text = inputs(
      document,
      `${TEXT}, input[type=tel], input[type=number]`,
    );
    const field =
      text.find((input) => input.autocomplete === "one-time-code") ??
      text.find((input) =>
        named(input, /otp|totp|2fa|mfa|one.?time|verification|code/i),
      );
    if (field) {
      setValue(field, request.code);
      filled.push("code");
    }
  }
  return { error: null, filled };
}

export interface TypedLogin {
  origin: string;
  username: string;
  password: string;
}

/** The username and password typed into the page, to save them. */
export function readPage(): TypedLogin | null {
  const usable = (input: HTMLInputElement) =>
    input.type !== "hidden" && input.getClientRects().length > 0;
  const password = Array.from(
    document.querySelectorAll<HTMLInputElement>("input[type=password]"),
  ).find((input) => usable(input) && input.value !== "");
  if (password == null) return null;
  const before = Array.from(
    (password.form ?? document).querySelectorAll<HTMLInputElement>(
      "input:not([type]), input[type=text], input[type=email]",
    ),
  ).filter(
    (input) =>
      usable(input) &&
      input.value !== "" &&
      input.compareDocumentPosition(password) &
        Node.DOCUMENT_POSITION_FOLLOWING,
  );
  const username =
    before.find((input) => /username|email/.test(input.autocomplete)) ??
    before[before.length - 1];
  return {
    origin: location.origin,
    username: username?.value.trim() ?? "",
    password: password.value,
  };
}
