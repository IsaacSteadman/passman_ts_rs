import { OTP_PERIOD_SECONDS, generateOtp, otpSecondsRemaining } from "./mfa";

// ── Data model ────────────────────────────────────────────────────────────────

export type PasswordCellData = { type: "mfa-key" | "password"; value: string };
export type LinkCellData = { url: string; text?: string };
export type CellValue = string | LinkCellData | PasswordCellData;

export type PassTableColumn = {
  id: string;
  label: string;
} & (
  | { type: "textarea"; data: string[] }
  | { type: "link"; data: LinkCellData[] }
  | { type: "password"; data: PasswordCellData[] }
);

export type PassTableData = {
  id: string;
  rowIds: string[];
  name: string;
  columns: PassTableColumn[];
};

export type HistoryEntry =
  | {
      kind: "cell-edit";
      timestamp: string;
      tableId: string;
      tableName: string;
      colId: string;
      colLabel: string;
      rowId: string;
      rowIndex: number;
      previousValue: CellValue;
      newValue: CellValue;
    }
  | {
      kind: "table-name";
      timestamp: string;
      tableId: string;
      previousName: string;
      newName: string;
    }
  | {
      kind: "row-add";
      timestamp: string;
      tableId: string;
      tableName: string;
      rowId: string;
      rowIndex: number;
    }
  | {
      kind: "row-delete";
      timestamp: string;
      tableId: string;
      tableName: string;
      rowId: string;
      rowIndex: number;
      cellSnapshot: { colId: string; colLabel: string; value: CellValue }[];
    }
  | {
      kind: "col-add";
      timestamp: string;
      tableId: string;
      tableName: string;
      colId: string;
      colLabel: string;
    }
  | {
      kind: "col-delete";
      timestamp: string;
      tableId: string;
      tableName: string;
      colMeta: { id: string; label: string; type: PassTableColumn["type"] };
      cellsByRowId: { rowId: string; value: CellValue }[];
      colIndex: number;
    }
  | {
      kind: "table-add";
      timestamp: string;
      tableId: string;
      tableName: string;
    }
  | {
      kind: "table-delete";
      timestamp: string;
      tableId: string;
      tableIndex: number;
      tableSnapshot: PassTableData;
    };

/** Someone whose sharing identity this user has checked in person (QR
 *  codes) or by comparing a safety number. */
export type SharingContact = {
  fingerprint: string;
  method: "qr" | "safety-number";
  verifiedAt: string;
};

/** A user's sharing identity and the people they've verified. */
export type SharingData = {
  /** The identity secret (URL-safe base64), from which its key pairs are
   *  derived; the public half is published on the server. */
  identitySecret: string;
  contacts: Record<string, SharingContact>;
};

export type VaultRoot = {
  tables: PassTableData[];
  history: HistoryEntry[];
  /** Only in a user's own vault, once they've set up sharing. */
  sharing?: SharingData;
};

export interface PassTableCallbacks {
  onFetchBeforeEdit: () => Promise<void>;
  onAction: (entry: HistoryEntry) => Promise<void>;
  /** Shows the table without any way to change it. */
  readOnly?: boolean;
}

/** A one-line description of a change, for history lists. */
export function describeHistoryEntry(entry: HistoryEntry): string {
  switch (entry.kind) {
    case "cell-edit":
      return `Edited "${entry.colLabel}" in "${entry.tableName}" row ${entry.rowIndex + 1}`;
    case "table-name":
      return `Renamed table "${entry.previousName}" → "${entry.newName}"`;
    case "row-add":
      return `Added row to "${entry.tableName}"`;
    case "row-delete":
      return `Deleted row ${entry.rowIndex + 1} from "${entry.tableName}"`;
    case "col-add":
      return `Added column "${entry.colLabel}" to "${entry.tableName}"`;
    case "col-delete":
      return `Deleted column "${entry.colMeta.label}" from "${entry.tableName}"`;
    case "table-add":
      return `Added table "${entry.tableName}"`;
    case "table-delete":
      return `Deleted table "${entry.tableSnapshot.name}"`;
  }
}

// ── Cell helpers ──────────────────────────────────────────────────────────────

export function getDefaultCellValue(type: PassTableColumn["type"]): CellValue {
  if (type === "textarea") return "";
  if (type === "link") return { url: "" };
  return { type: "password", value: "" };
}

/** Write a CellValue into the correctly-typed data array at rowIdx. */
export function setCellValue(
  col: PassTableColumn,
  rowIdx: number,
  value: CellValue,
): void {
  if (col.type === "textarea") col.data[rowIdx] = value as string;
  else if (col.type === "link") col.data[rowIdx] = value as LinkCellData;
  else col.data[rowIdx] = value as PasswordCellData;
}

/** Splice a CellValue into the correctly-typed data array at rowIdx. */
export function spliceCellValue(
  col: PassTableColumn,
  rowIdx: number,
  value: CellValue,
): void {
  if (col.type === "textarea") col.data.splice(rowIdx, 0, value as string);
  else if (col.type === "link")
    col.data.splice(rowIdx, 0, value as LinkCellData);
  else col.data.splice(rowIdx, 0, value as PasswordCellData);
}

/** Deep equality check for CellValue (string | LinkCellData | PasswordCellData). */
export function cellValuesEqual(a: CellValue, b: CellValue): boolean {
  if (typeof a === "string" || typeof b === "string") return a === b;
  if ("type" in a && "type" in b)
    // Both PasswordCellData
    return a.type === b.type && a.value === b.value;
  if (!("type" in a) && !("type" in b))
    // Both LinkCellData
    return a.url === b.url && a.text === b.text;
  return false; // mixed kinds
}

// ── Icons ─────────────────────────────────────────────────────────────────────
// Heroicons 2.x outline 24px — MIT License, Copyright (c) Tailwind Labs, Inc.
// https://github.com/tailwindlabs/heroicons
const ICON_PATH = {
  trash:
    "m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0",
  xmark: "M6 18 18 6M6 6l12 12",
  plus: "M12 4.5v15m7.5-7.5h-15",
  eye: "M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178ZM15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z",
  eyeSlash:
    "M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88",
  copy: "M11.35 3.836c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75 2.25 2.25 0 0 0-.1-.664m-5.8 0A2.251 2.251 0 0 1 13.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m8.9-4.414c.376.023.75.05 1.124.08 1.131.094 1.976 1.057 1.976 2.192V16.5A2.25 2.25 0 0 1 18 18.75h-2.25m-7.5-10.5H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V18.75m-7.5-10.5h6.375c.621 0 1.125.504 1.125 1.125v9.375",
} as const;

type IconName = keyof typeof ICON_PATH;

function svgIcon(d: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="${d}"/></svg>`;
}

function iconBtn(
  icon: IconName,
  title: string,
  ...extra: string[]
): HTMLButtonElement {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = ["pm-icon-btn", ...extra].filter(Boolean).join(" ");
  btn.innerHTML = svgIcon(ICON_PATH[icon]);
  btn.title = title;
  return btn;
}

function addBtn(icon: IconName, label: string): HTMLButtonElement {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "pm-add-btn";
  btn.innerHTML = svgIcon(ICON_PATH[icon]) + label;
  return btn;
}

let clipboardWriter: ((text: string) => void) | null = null;

/** Replaces how copied text reaches the clipboard (the Android app marks it
 *  sensitive and clears it again). */
export function setClipboardWriter(writer: (text: string) => void): void {
  clipboardWriter = writer;
}

export function copyTextToClipboard(text: string) {
  if (clipboardWriter) {
    clipboardWriter(text);
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
    console.log("copy password successful");
    return;
  }
  window.getSelection()?.removeAllRanges();
  const pre = document.createElement("pre");
  pre.innerText = text;
  const range = document.createRange();
  range.selectNode(pre);
  window.getSelection()?.addRange(range);
  try {
    const successful = document.execCommand("copy");
    console.log(`copy password ${successful ? "successful" : "unsuccessful"}`);
  } catch (err) {
    console.log("copy password error", err);
  }
  window.getSelection()?.removeAllRanges();
  pre.remove();
}

function renderTextAreaEdit(td: HTMLTableCellElement, data: string) {
  const input = document.createElement("textarea");
  input.value = data;
  td.appendChild(input);
}

// A link is clickable inside the unlocked app, so schemes that run code
// (javascript:, data:, …) must never be saved or rendered as a link.
const ALLOWED_LINK_SCHEMES = [
  "http:",
  // logins for Android apps (android://<signing key hash>@<package name>/)
  "android:",
  "https:",
  "mailto:",
  "ftp:",
  "sftp:",
  "ftps:",
  "tel:",
  "sms:",
];

/** The scheme the browser would navigate with, or null if `url` won't parse.
 *  Uses the URL parser rather than a prefix check because the parser ignores
 *  case and strips leading control characters, exactly as a click would. */
function linkScheme(url: string): string | null {
  try {
    return new URL(url).protocol;
  } catch {
    return null;
  }
}

function isAllowedLinkUrl(url: string): boolean {
  const scheme = linkScheme(url);
  return scheme != null && ALLOWED_LINK_SCHEMES.includes(scheme);
}

function validateUrl(url: string): string | null {
  // empty means "no link" (new cells start empty)
  if (!url) return null;
  if (/\s/.test(url)) {
    return "URL cannot contain whitespace";
  }
  const scheme = linkScheme(url);
  if (scheme == null) {
    return "Invalid URL format (include the scheme, e.g. https://)";
  }
  if (!ALLOWED_LINK_SCHEMES.includes(scheme)) {
    return `URL must start with one of: ${ALLOWED_LINK_SCHEMES.join(" ")}`;
  }
  return null;
}

function validateMfaKey(key: string): string | null {
  if (!key) return null;
  if (!/^[A-Z2-7\s]+=*$/i.test(key)) {
    return "MFA key must be a Base32 string (letters A-Z and digits 2-7)";
  }
  return null;
}

function renderLinkEdit(td: HTMLTableCellElement, data: LinkCellData) {
  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.value = data.url;
  urlInput.placeholder = "https://\u2026";

  const urlError = document.createElement("span");
  urlError.className = "pm-field-error";
  urlError.textContent = validateUrl(data.url) ?? "";
  urlInput.addEventListener("input", () => {
    urlError.textContent = validateUrl(urlInput.value) ?? "";
  });

  const labelInput = document.createElement("input");
  labelInput.type = "text";
  labelInput.value = data.text ?? "";
  labelInput.placeholder = "Display label (optional)";
  labelInput.style.marginTop = "0.3em";

  td.append(urlInput, urlError, labelInput);
}

function renderPasswordEdit(td: HTMLTableCellElement, data: PasswordCellData) {
  const select = document.createElement("select");
  const optPassword = document.createElement("option");
  optPassword.value = "password";
  optPassword.text = "Password";
  const optMfa = document.createElement("option");
  optMfa.value = "mfa-key";
  optMfa.text = "MFA Key";
  select.append(optPassword, optMfa);
  select.value = data.type;

  const input = document.createElement("input");
  input.type = data.type === "mfa-key" ? "text" : "password";
  input.value = data.value;

  const errorSpan = document.createElement("span");
  errorSpan.className = "pm-field-error";

  function updateValidation() {
    if (select.value === "mfa-key") {
      input.type = "text";
      errorSpan.textContent = validateMfaKey(input.value) ?? "";
    } else {
      input.type = "password";
      errorSpan.textContent = "";
    }
  }

  updateValidation();
  select.addEventListener("change", updateValidation);
  input.addEventListener("input", updateValidation);

  td.append(select, input, errorSpan);
}

function renderColCellEdit(
  td: HTMLTableCellElement,
  col: PassTableColumn,
  rowIndex: number,
) {
  if (col.type === "textarea") {
    renderTextAreaEdit(td, col.data[rowIndex]);
  } else if (col.type === "link") {
    renderLinkEdit(td, col.data[rowIndex]);
  } else if (col.type === "password") {
    renderPasswordEdit(td, col.data[rowIndex]);
  }
}

function unRenderColCellEdit(
  td: HTMLTableCellElement,
  col: PassTableColumn,
  rowIndex: number,
) {
  if (col.type === "textarea") {
    col.data[rowIndex] = td.getElementsByTagName("textarea")[0].value;
  } else if (col.type === "link") {
    const [urlInput, textInput] = td.getElementsByTagName("input");
    const url = urlInput.value;
    const text = textInput.value;
    col.data[rowIndex] = text.length ? { url, text } : { url };
  } else if (col.type === "password") {
    const select = td.getElementsByTagName("select")[0];
    const input = td.getElementsByTagName("input")[0];
    col.data[rowIndex] = {
      type: select.value as "password" | "mfa-key",
      value: input.value,
    };
  }
}

function newCell(col: PassTableColumn) {
  if (col.type === "textarea") {
    col.data.push("");
  } else if (col.type === "link") {
    col.data.push({ url: "" });
  } else if (col.type === "password") {
    col.data.push({ type: "password", value: "" });
  }
}

// ── Cell read-mode rendering ──────────────────────────────────────────────────

function renderTextArea(td: HTMLTableCellElement, data: string) {
  if (!data) {
    const s = document.createElement("span");
    s.textContent = "—";
    s.className = "pm-placeholder";
    td.appendChild(s);
  } else {
    td.innerText = data;
  }
}

function renderLink(td: HTMLTableCellElement, data: LinkCellData) {
  if (!data.url) {
    const s = document.createElement("span");
    s.textContent = "—";
    s.className = "pm-placeholder";
    td.appendChild(s);
    return;
  }
  if (!isAllowedLinkUrl(data.url)) {
    // saved before schemes were checked: show it, but not as a link
    const s = document.createElement("span");
    s.textContent = data.text ?? data.url;
    s.title = `Not a clickable link: ${data.url}`;
    td.appendChild(s);
    return;
  }
  const a = document.createElement("a");
  a.href = data.url;
  a.innerText = data.text ?? data.url;
  // the opened page gets no handle on this tab and no Referer
  a.rel = "noopener noreferrer";
  if (a.protocol === "http:" || a.protocol === "https:") a.target = "_blank";
  td.appendChild(a);
}

function renderPassword(td: HTMLTableCellElement, data: PasswordCellData) {
  if (!data.value) {
    const s = document.createElement("span");
    s.textContent = "—";
    s.className = "pm-placeholder";
    td.appendChild(s);
    return;
  }
  if (data.type === "mfa-key") {
    renderMfaKey(td, data.value);
    return;
  }
  const span = document.createElement("span");
  span.textContent = `Password: ${maskSecret(data.value)}`;
  span.style.fontFamily = "monospace";
  const copyBtn = iconBtn("copy", "Copy password");
  copyBtn.addEventListener("click", () => {
    copyTextToClipboard(data.value);
    flashCopied(copyBtn);
  });
  td.append(span, " ", copyBtn);
}

function maskSecret(value: string): string {
  return (
    "\u2022".repeat(Math.min(12, value.length)) +
    (value.length > 12 ? "\u2026" : "")
  );
}

function flashCopied(button: HTMLButtonElement): void {
  button.classList.add("pm-copied");
  setTimeout(() => {
    button.classList.remove("pm-copied");
  }, 700);
}

const RING_RADIUS = 8;
const RING_LENGTH = 2 * Math.PI * RING_RADIUS;

/** An MFA key: copying copies the current code, which can also be shown,
 *  with the time left until it changes. */
function renderMfaKey(td: HTMLTableCellElement, key: string) {
  const masked = document.createElement("span");
  masked.textContent = `MFA Key: ${maskSecret(key)}`;
  masked.style.fontFamily = "monospace";

  const otp = document.createElement("span");
  otp.className = "pm-otp";
  otp.hidden = true;
  const code = document.createElement("span");
  code.className = "pm-otp-code";
  const timer = document.createElement("span");
  timer.className = "pm-otp-timer";
  timer.title = "Seconds until the next code";
  timer.innerHTML = `<svg viewBox="0 0 20 20" aria-hidden="true"><circle class="pm-otp-track" cx="10" cy="10" r="${RING_RADIUS}"/><circle class="pm-otp-left" cx="10" cy="10" r="${RING_RADIUS}" stroke-dasharray="${RING_LENGTH}"/></svg>`;
  const ringLeft = timer.querySelector(".pm-otp-left") as SVGCircleElement;
  const seconds = document.createElement("span");
  timer.append(seconds);
  otp.append(code, timer);

  const showBtn = iconBtn("eye", "Show code");
  const copyBtn = iconBtn("copy", "Copy code");

  let timeout: ReturnType<typeof setTimeout> | undefined;
  let shownPeriod = -1;

  async function tick(): Promise<void> {
    // gone after re-rendering or locking
    if (!td.isConnected) return hide();
    const now = Date.now();
    const left = otpSecondsRemaining(now);
    seconds.textContent = String(left);
    ringLeft.style.strokeDashoffset = String(
      RING_LENGTH * (1 - left / OTP_PERIOD_SECONDS),
    );
    timer.classList.toggle("pm-otp-expiring", left <= 5);
    // next tick just after the next whole second, when the code may change
    timeout = setTimeout(tick, 1000 - (now % 1000) + 20);
    const period = Math.floor(now / 1000 / OTP_PERIOD_SECONDS);
    if (period === shownPeriod) return;
    shownPeriod = period;
    try {
      const value = await generateOtp(key, now);
      code.textContent = `${value.slice(0, 3)} ${value.slice(3)}`;
      code.classList.remove("pm-otp-invalid");
    } catch {
      code.textContent = "Invalid MFA key";
      code.classList.add("pm-otp-invalid");
    }
  }

  function show(): void {
    masked.hidden = true;
    otp.hidden = false;
    showBtn.innerHTML = svgIcon(ICON_PATH.eyeSlash);
    showBtn.title = "Hide code";
    void tick();
  }

  function hide(): void {
    clearTimeout(timeout);
    timeout = undefined;
    shownPeriod = -1;
    code.textContent = "";
    otp.hidden = true;
    masked.hidden = false;
    showBtn.innerHTML = svgIcon(ICON_PATH.eye);
    showBtn.title = "Show code";
  }

  showBtn.addEventListener("click", () => {
    if (otp.hidden) show();
    else hide();
  });
  copyBtn.addEventListener("click", async () => {
    try {
      copyTextToClipboard(await generateOtp(key));
      flashCopied(copyBtn);
    } catch {
      copyBtn.title = "Invalid MFA key: no code to copy";
    }
  });
  td.append(masked, otp, " ", showBtn, copyBtn);
}

function renderColCell(
  td: HTMLTableCellElement,
  col: PassTableColumn,
  rowIndex: number,
) {
  if (col.type === "textarea") {
    renderTextArea(td, col.data[rowIndex]);
  } else if (col.type === "link") {
    renderLink(td, col.data[rowIndex]);
  } else if (col.type === "password") {
    renderPassword(td, col.data[rowIndex]);
  }
}

// ── Inline cell editing ────────────────────────────────────────────────────────

function makeCellEditable(
  td: HTMLTableCellElement,
  col: PassTableColumn,
  data: PassTableData,
  callbacks: PassTableCallbacks,
): void {
  td.tabIndex = 0;
  let editingActive = false;

  // ── Visual selected state ─────────────────────────────────────────────────
  td.addEventListener("focus", () => td.classList.add("pm-cell-selected"));
  td.addEventListener("blur", () => {
    // Don't remove during editing: focus has moved to a child input, not away.
    if (!editingActive) td.classList.remove("pm-cell-selected");
  });

  function enterEditMode() {
    if (editingActive) return;
    editingActive = true;

    // onFetchBeforeEdit now returns immediately; the background fetch (if any)
    // runs concurrently and will flag a conflict in the status bar if needed.
    callbacks.onFetchBeforeEdit().then(() => {
      // Compute row index dynamically so prior insertions/deletions don't
      // shift us onto the wrong row.
      const tr = td.closest("tr") as HTMLTableRowElement;
      const rowIndex = tr.rowIndex - 1;

      // Snapshot the old value and stable row identity before mutating.
      const oldValue = structuredClone(col.data[rowIndex]) as CellValue;
      const rowId = data.rowIds[rowIndex];

      td.innerHTML = "";
      td.classList.add("pm-cell-editing");
      renderColCellEdit(td, col, rowIndex);

      // Focus the right element.
      // Password: skip the <select>, focus the first <input>.
      if (col.type === "textarea") {
        (td.querySelector("textarea") as HTMLElement | null)?.focus();
      } else if (col.type === "link") {
        (td.querySelector("input") as HTMLElement | null)?.focus();
      } else {
        (td.querySelectorAll("input")[0] as HTMLElement | undefined)?.focus();
      }

      // refocusTd=true: Enter key committed — keep cell selected for keyboard nav.
      // refocusTd=false: focusout committed — focus moved elsewhere, clean up class.
      function commit(refocusTd = false) {
        if (!editingActive) return;
        // An invalid link stays in edit mode (with its error shown) rather
        // than being saved.
        if (col.type === "link") {
          const urlInput = td.getElementsByTagName("input")[0];
          if (validateUrl(urlInput.value) != null) {
            if (refocusTd) urlInput.focus();
            return;
          }
        }
        editingActive = false;
        td.removeEventListener("focusout", onFocusOut);

        const currentRowIndex =
          (td.closest("tr") as HTMLTableRowElement).rowIndex - 1;
        unRenderColCellEdit(td, col, currentRowIndex);
        const newValue = structuredClone(
          col.data[currentRowIndex],
        ) as CellValue;

        td.innerHTML = "";
        td.classList.remove("pm-cell-editing");
        renderColCell(td, col, currentRowIndex);

        if (refocusTd) {
          td.focus(); // Keeps cell selected; focus listener re-adds the class.
        } else {
          td.classList.remove("pm-cell-selected"); // Focus moved elsewhere.
        }

        // Skip save + history if nothing actually changed.
        if (!cellValuesEqual(newValue, oldValue)) {
          callbacks.onAction({
            kind: "cell-edit",
            timestamp: new Date().toISOString(),
            tableId: data.id,
            tableName: data.name,
            colId: col.id,
            colLabel: col.label,
            rowId,
            rowIndex: currentRowIndex,
            previousValue: oldValue,
            newValue,
          });
        }
      }

      function cancel() {
        if (!editingActive) return;
        editingActive = false;
        td.removeEventListener("focusout", onFocusOut);
        td.innerHTML = "";
        td.classList.remove("pm-cell-editing");
        const currentRowIndex =
          (td.closest("tr") as HTMLTableRowElement).rowIndex - 1;
        renderColCell(td, col, currentRowIndex);
        td.focus(); // Restore selected state after cancel.
      }

      function onFocusOut(e: FocusEvent) {
        // Ignore focus moves that stay inside the same cell (e.g. select→input
        // in password cells).
        if (e.relatedTarget instanceof Node && td.contains(e.relatedTarget))
          return;
        commit(false);
      }

      td.addEventListener("focusout", onFocusOut);

      td.querySelectorAll<HTMLElement>("input, textarea, select").forEach(
        (el) => {
          el.addEventListener("keydown", (ev) => {
            const e = ev as KeyboardEvent;
            if (e.key === "Escape") {
              e.stopPropagation();
              cancel();
            } else if (e.key === "Enter") {
              if (col.type === "textarea") {
                // Only commit on Cmd+Enter / Ctrl+Enter; plain Enter inserts newline.
                if (e.metaKey || e.ctrlKey) {
                  e.preventDefault();
                  commit(true);
                }
              } else if (el.tagName !== "SELECT") {
                e.preventDefault();
                commit(true);
              }
            }
          });
        },
      );
    });
  }

  // ── Click-to-select, click-again-to-edit ─────────────────────────────────
  // pointerdown fires before the browser moves focus on tap/click, so we can
  // reliably check whether the cell was already focused before this event.
  let wasAlreadyFocused = false;
  td.addEventListener("pointerdown", () => {
    wasAlreadyFocused = document.activeElement === td;
  });
  td.addEventListener("click", () => {
    if (wasAlreadyFocused && !editingActive) enterEditMode();
  });

  td.addEventListener("keydown", (e) => {
    // Only trigger when the td itself is focused, not a child input.
    if (e.target !== td) return;
    if (e.key === "F2" || e.key === "Enter") {
      e.preventDefault();
      enterEditMode();
    }
  });
}

// ── Delete button ─────────────────────────────────────────────────────────────

function renderDeleteButton(
  td: HTMLTableCellElement,
  data: PassTableData,
  callbacks: PassTableCallbacks,
): void {
  const delBtn = iconBtn("trash", "Delete row", "pm-danger");
  delBtn.addEventListener("click", async () => {
    const tr = td.closest("tr") as HTMLTableRowElement;
    const rowIndex = tr.rowIndex - 1;
    const rowId = data.rowIds[rowIndex];
    const cellSnapshot = data.columns.map((c) => ({
      colId: c.id,
      colLabel: c.label,
      value: structuredClone(c.data[rowIndex]) as CellValue,
    }));
    data.columns.forEach((c) => c.data.splice(rowIndex, 1));
    data.rowIds.splice(rowIndex, 1);
    tr.remove();
    await callbacks.onAction({
      kind: "row-delete",
      timestamp: new Date().toISOString(),
      tableId: data.id,
      tableName: data.name,
      rowId,
      rowIndex,
      cellSnapshot,
    });
  });
  td.appendChild(delBtn);
}

export function createSelect<T extends string>(
  options: Record<T, string>,
  value: T,
): HTMLSelectElement & { value: T } {
  const select = document.createElement("select");
  for (const key in options) {
    const option = document.createElement("option");
    option.value = key;
    option.innerText = options[key];
    if (key === value) {
      option.selected = true;
    }
    select.appendChild(option);
  }
  return select as HTMLSelectElement & { value: T };
}

export function renderPassTable(
  data: PassTableData,
  dom: HTMLDivElement,
  callbacks: PassTableCallbacks,
  onDelete?: () => void,
) {
  // ── Card ──────────────────────────────────────────────────────────────────
  const card = document.createElement("div");
  card.className = "pm-card";

  const cardHeader = document.createElement("div");
  cardHeader.className = "pm-card-header";

  const nameEl = document.createElement("span");
  nameEl.className = "pm-card-name";
  nameEl.contentEditable = callbacks.readOnly ? "false" : "true";
  nameEl.textContent = data.name;
  nameEl.addEventListener("focus", () => {
    callbacks.onFetchBeforeEdit();
  });
  nameEl.addEventListener("blur", () => {
    const previousName = data.name;
    const trimmed = nameEl.textContent?.trim() ?? "";
    const newName = trimmed || previousName;
    data.name = newName;
    nameEl.textContent = newName;
    if (newName !== previousName) {
      callbacks.onAction({
        kind: "table-name",
        timestamp: new Date().toISOString(),
        tableId: data.id,
        previousName,
        newName,
      });
    }
  });
  nameEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      (nameEl as HTMLElement).blur();
    }
  });

  const addColBtn = addBtn("plus", "Add Column");
  const addRowBtn = addBtn("plus", "Add Row");
  cardHeader.append(nameEl);
  if (!callbacks.readOnly) cardHeader.append(addColBtn, addRowBtn);
  if (onDelete && !callbacks.readOnly) {
    const delTableBtn = iconBtn("trash", "Delete table", "pm-danger");
    delTableBtn.addEventListener("click", onDelete);
    cardHeader.appendChild(delTableBtn);
  }
  card.appendChild(cardHeader);

  // ── Table ─────────────────────────────────────────────────────────────────
  const table = document.createElement("table");
  table.className = "pm-table";
  const thead = table.createTHead();
  const tbody = table.createTBody();
  const headTr = thead.insertRow();

  function makeColTh(col: PassTableColumn): HTMLTableCellElement {
    const th = document.createElement("th");
    th.textContent = col.label + " ";
    const removeBtn = iconBtn("xmark", "Remove column", "pm-danger");
    removeBtn.addEventListener("click", async () => {
      const colIdx = th.cellIndex;
      const colMeta = { id: col.id, label: col.label, type: col.type };
      const cellsByRowId = data.rowIds.map((rowId, rowIdx) => ({
        rowId,
        value: structuredClone(col.data[rowIdx]) as CellValue,
      }));
      const tableName = data.name;
      data.columns.splice(colIdx, 1);
      headTr.deleteCell(colIdx);
      if (data.columns.length) {
        for (let rowIdx = 0; rowIdx < cellsByRowId.length; ++rowIdx) {
          tbody.rows[rowIdx]?.deleteCell(colIdx);
        }
      } else {
        tbody.innerHTML = "";
      }
      await callbacks.onAction({
        kind: "col-delete",
        timestamp: new Date().toISOString(),
        tableId: data.id,
        tableName,
        colMeta,
        cellsByRowId,
        colIndex: colIdx,
      });
    });
    if (!callbacks.readOnly) th.appendChild(removeBtn);
    return th as unknown as HTMLTableCellElement;
  }

  // ── Add Column modal ──────────────────────────────────────────────────────
  addColBtn.addEventListener("click", () => {
    if (document.getElementById("pm-modal")) return;

    const backdrop = document.createElement("div");
    backdrop.id = "pm-modal";
    backdrop.className = "pm-backdrop";
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.remove();
    });

    const modal = document.createElement("div");
    modal.className = "pm-modal";

    const title = document.createElement("h3");
    title.textContent = "Add Column";

    const nameField = document.createElement("div");
    nameField.className = "pm-field";
    const nameLabel = document.createElement("label");
    nameLabel.textContent = "Column name";
    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "e.g. Username";
    nameField.append(nameLabel, nameInput);

    const typeField = document.createElement("div");
    typeField.className = "pm-field";
    const typeLabel = document.createElement("label");
    typeLabel.textContent = "Column type";
    const typeSelect = createSelect<PassTableColumn["type"]>(
      { link: "Link / URL", password: "Password / MFA Key", textarea: "Text" },
      "textarea",
    );
    typeField.append(typeLabel, typeSelect);

    const errorEl = document.createElement("p");
    errorEl.className = "pm-modal-error";

    const footer = document.createElement("div");
    footer.className = "pm-modal-footer";
    const cancelBtn = document.createElement("button");
    cancelBtn.className = "pm-btn pm-btn-ghost";
    cancelBtn.type = "button";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", () => backdrop.remove());
    const submitBtn = document.createElement("button");
    submitBtn.className = "pm-btn pm-btn-primary";
    submitBtn.type = "button";
    submitBtn.textContent = "Add Column";
    submitBtn.addEventListener("click", async () => {
      const colName = nameInput.value.trim();
      if (!colName) {
        errorEl.textContent = "Column name cannot be empty.";
        return;
      }
      const col = {
        id: crypto.randomUUID(),
        data: [],
        label: colName,
        type: typeSelect.value,
      } as unknown as PassTableColumn;
      data.columns.push(col);
      headTr.insertBefore(
        makeColTh(col),
        headTr.cells[headTr.cells.length - 1],
      );
      for (let rowIdx = 0; rowIdx < data.rowIds.length; rowIdx++) {
        const tr = tbody.rows[rowIdx];
        newCell(col);
        const td = tr.insertCell(data.columns.length - 1);
        td.className = "pm-td-data";
        renderColCell(td, col, rowIdx);
        makeCellEditable(td, col, data, callbacks);
      }
      backdrop.remove();
      await callbacks.onAction({
        kind: "col-add",
        timestamp: new Date().toISOString(),
        tableId: data.id,
        tableName: data.name,
        colId: col.id,
        colLabel: col.label,
      });
    });
    nameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submitBtn.click();
    });

    footer.append(cancelBtn, submitBtn);
    modal.append(title, nameField, typeField, errorEl, footer);
    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);
    nameInput.focus();
  });

  // ── Add Row ───────────────────────────────────────────────────────────────
  addRowBtn.addEventListener("click", async () => {
    const rowId = crypto.randomUUID();
    const rowIndex = data.rowIds.length;
    data.rowIds.push(rowId);
    data.columns.forEach((col) => newCell(col));

    const tr = tbody.insertRow();
    data.columns.forEach((col) => {
      const td = tr.insertCell();
      td.className = "pm-td-data";
      renderColCell(td, col, rowIndex);
      makeCellEditable(td, col, data, callbacks);
    });
    const actTd = tr.insertCell();
    actTd.className = "pm-td-actions";
    if (!callbacks.readOnly) renderDeleteButton(actTd, data, callbacks);

    await callbacks.onAction({
      kind: "row-add",
      timestamp: new Date().toISOString(),
      tableId: data.id,
      tableName: data.name,
      rowId,
      rowIndex,
    });
  });

  // ── Validate & render initial state ───────────────────────────────────────
  if (
    data.columns.length &&
    !data.columns
      .slice(1)
      .every((col) => col.data.length === data.columns[0].data.length)
  ) {
    throw new Error("All columns must have the same number of data entries.");
  }

  data.columns.forEach((col) => {
    headTr.appendChild(makeColTh(col));
    for (let rowIdx = 0; rowIdx < col.data.length; rowIdx++) {
      const tr = tbody.rows[rowIdx] ?? tbody.insertRow();
      const td = tr.insertCell();
      td.className = "pm-td-data";
      renderColCell(td, col, rowIdx);
      if (!callbacks.readOnly) makeCellEditable(td, col, data, callbacks);
    }
  });

  headTr.appendChild(document.createElement("th")); // actions column header

  const numRows = data.columns.length ? data.columns[0].data.length : 0;
  for (let i = 0; i < numRows; i++) {
    const actTd = tbody.rows[i].insertCell();
    actTd.className = "pm-td-actions";
    if (!callbacks.readOnly) renderDeleteButton(actTd, data, callbacks);
  }

  card.appendChild(table);
  dom.appendChild(card);
}
