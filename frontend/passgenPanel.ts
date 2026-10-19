import {
  type PassgenOptions,
  type PassgenLength,
  passgen,
  estimateBits,
  estimateChars,
} from "./passgen_util";
import { type PassTableData, copyTextToClipboard } from "./PassTable";

const DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\";

/** Sets up the passgen panel. `getTableData` is called each time to get the current live data. */
export interface PassgenPanelHandle {
  /** Forgets the generated password and the vault's table names (logout). */
  clear(): void;
}

export function initPassgenPanel(
  getTableData: () => PassTableData[] | null,
): PassgenPanelHandle {
  const panel = document.querySelector("div#passgen-panel") as HTMLDivElement;
  const form = panel.querySelector("form")!;

  const symbolCharsetInput = form.querySelector(
    "input[name='symbol-charset']",
  ) as HTMLInputElement;
  const resetCharsetBtn = form.querySelector(
    "[name='reset-charset']",
  ) as HTMLElement;
  const bitlengthInput = form.querySelector(
    "input[name='bitlength']",
  ) as HTMLInputElement;
  const passlengthInput = form.querySelector(
    "input[name='passlength']",
  ) as HTMLInputElement;
  const derivedCharsDisplay = form.querySelector(
    "[name='derived-chars-display']",
  ) as HTMLElement;
  const derivedBitsDisplay = form.querySelector(
    "[name='derived-bits-display']",
  ) as HTMLElement;
  const chkUpper = form.querySelector(
    "input[name='chk-upper']",
  ) as HTMLInputElement;
  const chkLower = form.querySelector(
    "input[name='chk-lower']",
  ) as HTMLInputElement;
  const chkDigit = form.querySelector(
    "input[name='chk-digit']",
  ) as HTMLInputElement;
  const chkSymbol = form.querySelector(
    "input[name='chk-symbol']",
  ) as HTMLInputElement;
  const chkSpaces = form.querySelector(
    "input[name='chk-spaces']",
  ) as HTMLInputElement;
  const selLetters = form.querySelector(
    "select[name='sel-letters-allowed']",
  ) as HTMLSelectElement;
  const generateBtn = form.querySelector("[name='generate']") as HTMLElement;
  const passwordOutput = form.querySelector(
    "input[name='password']",
  ) as HTMLInputElement;
  const addTableSelect = form.querySelector(
    "select[name='password-add-table']",
  ) as HTMLSelectElement;
  const addToTableBtn = form.querySelector(
    "[name='add-to-table']",
  ) as HTMLElement;
  const copyPasswordBtn = form.querySelector(
    "[name='copy-password']",
  ) as HTMLElement;
  const genModeRadios = form.querySelectorAll(
    "input[name='gen-mode']",
  ) as NodeListOf<HTMLInputElement>;
  const modeRowBits = form.querySelector(
    ".pg-mode-row[data-mode='bits']",
  ) as HTMLElement;
  const modeRowChars = form.querySelector(
    ".pg-mode-row[data-mode='chars']",
  ) as HTMLElement;

  symbolCharsetInput.value = DEFAULT_SYMBOLS;

  // ----- Mode -----
  function currentMode(): "bits" | "chars" {
    for (const r of genModeRadios) {
      if (r.checked) return r.value as "bits" | "chars";
    }
    return "bits";
  }

  // ----- Read form state -----
  function readPassgenOpts(): PassgenOptions {
    return {
      symbols: symbolCharsetInput.value,
      lettersAllowed: selLetters.value as "all" | "only-lower" | "only-upper",
      mustUpper: chkUpper.checked,
      mustLower: chkLower.checked,
      mustDigit: chkDigit.checked,
      mustSymbol: chkSymbol.checked,
      canSpaces: chkSpaces.checked,
    };
  }

  function readPassgenLength(): PassgenLength {
    if (currentMode() === "bits") {
      return { type: "bits", nBits: parseInt(bitlengthInput.value, 10) };
    }
    return { type: "nchars", nChars: parseInt(passlengthInput.value, 10) };
  }

  // ----- Derived display -----
  // Uses estimateChars / estimateBits from passgen_util so the hint reflects
  // the same model used during generation: required characters occupy slots
  // within the requested total, not on top of it.
  function updateDerivedDisplay(): void {
    const mode = currentMode();
    bitlengthInput.disabled = mode === "chars";
    passlengthInput.disabled = mode === "bits";

    modeRowBits.classList.toggle("pg-mode-row--active", mode === "bits");
    modeRowBits.classList.toggle("pg-mode-row--inactive", mode === "chars");
    modeRowChars.classList.toggle("pg-mode-row--active", mode === "chars");
    modeRowChars.classList.toggle("pg-mode-row--inactive", mode === "bits");

    const activeDisplay =
      mode === "bits" ? derivedCharsDisplay : derivedBitsDisplay;
    const inactiveDisplay =
      mode === "bits" ? derivedBitsDisplay : derivedCharsDisplay;
    inactiveDisplay.textContent = "";
    inactiveDisplay.classList.remove("pg-hint--warn");

    const opts = readPassgenOpts();

    // The only impossible combination: mustSymbol requires at least one symbol
    // character to be defined. mustUpper/Lower/Digit are always satisfiable
    // because passgen_util samples them from their own dedicated alphabets
    // regardless of the lettersAllowed setting.
    if (opts.mustSymbol && opts.symbols.length === 0) {
      activeDisplay.classList.add("pg-hint--warn");
      activeDisplay.textContent = "⚠ impossible: no symbols defined";
      return;
    }
    activeDisplay.classList.remove("pg-hint--warn");

    const requiredCount = [
      opts.mustUpper,
      opts.mustLower,
      opts.mustDigit,
      opts.mustSymbol,
    ].filter(Boolean).length;
    const requiredNote =
      requiredCount > 0 ? ` (incl. ${requiredCount} required)` : "";

    if (mode === "bits") {
      const bits = parseInt(bitlengthInput.value, 10);
      if (!isNaN(bits) && bits > 0) {
        // estimateChars accounts for required slots using smaller alphabets,
        // so the result is the correct total char count including those slots.
        const raw = estimateChars(bits, opts);
        const lo = Math.max(requiredCount, Math.floor(raw));
        const hi = Math.max(requiredCount, Math.ceil(raw));
        const range = lo === hi ? `${lo}` : `${lo}-${hi}`;
        activeDisplay.textContent = `estimated ${range} chars total${requiredNote}`;
      } else {
        activeDisplay.textContent = "";
      }
    } else {
      const nChars = parseInt(passlengthInput.value, 10);
      if (!isNaN(nChars) && nChars > 0) {
        // estimateBits accounts for required slots contributing less entropy
        // than a free slot, giving an honest total bit estimate.
        const raw = estimateBits(nChars, opts);
        const lo = Math.floor(raw);
        const hi = Math.ceil(raw);
        const range = lo === hi ? `${lo}` : `${lo}-${hi}`;
        activeDisplay.textContent = `estimated ${range} bits total${requiredNote}`;
      } else {
        activeDisplay.textContent = "";
      }
    }
  }

  // Wire all inputs that affect mode or charset/length
  genModeRadios.forEach((r) =>
    r.addEventListener("change", updateDerivedDisplay),
  );
  bitlengthInput.addEventListener("input", updateDerivedDisplay);
  passlengthInput.addEventListener("input", updateDerivedDisplay);
  symbolCharsetInput.addEventListener("input", updateDerivedDisplay);
  selLetters.addEventListener("change", updateDerivedDisplay);
  [chkUpper, chkLower, chkDigit, chkSymbol, chkSpaces].forEach((chk) =>
    chk.addEventListener("change", updateDerivedDisplay),
  );

  resetCharsetBtn.addEventListener("click", () => {
    symbolCharsetInput.value = DEFAULT_SYMBOLS;
    updateDerivedDisplay();
  });

  copyPasswordBtn.addEventListener("click", () => {
    copyTextToClipboard(passwordOutput.value);
  });

  updateDerivedDisplay();

  // ----- Generate -----
  generateBtn.addEventListener("click", () => {
    const opts = readPassgenOpts();
    const mode = currentMode();
    const activeDisplay =
      mode === "bits" ? derivedCharsDisplay : derivedBitsDisplay;

    if (opts.mustSymbol && opts.symbols.length === 0) {
      activeDisplay.classList.add("pg-hint--warn");
      activeDisplay.textContent = "⚠ impossible: no symbols defined";
      passwordOutput.value = "";
      return;
    }

    const length = readPassgenLength();
    if (length.type === "bits" && (isNaN(length.nBits) || length.nBits <= 0)) {
      activeDisplay.textContent =
        "Error: bit length must be a positive number.";
      passwordOutput.value = "";
      return;
    }
    if (
      length.type === "nchars" &&
      (isNaN(length.nChars) || length.nChars <= 0)
    ) {
      activeDisplay.textContent =
        "Error: character length must be a positive number.";
      passwordOutput.value = "";
      return;
    }

    try {
      passwordOutput.value = passgen(opts, length);
    } catch (e) {
      passwordOutput.value = "";
      activeDisplay.textContent = `Error: ${e}`;
      return;
    }
    updateDerivedDisplay();
  });

  // ----- Populate table select -----
  function refreshTableSelect(): void {
    const data = getTableData();
    while (addTableSelect.options.length > 1) addTableSelect.remove(1);
    if (data) {
      for (const table of data) {
        const opt = document.createElement("option");
        opt.value = table.name;
        opt.textContent = table.name;
        addTableSelect.appendChild(opt);
      }
    }
  }

  panel.addEventListener("mouseover", refreshTableSelect, { once: false });
  generateBtn.addEventListener("click", refreshTableSelect);

  // ----- Add to table -----
  addToTableBtn.addEventListener("click", () => {
    const pw = passwordOutput.value;
    const activeDisplay =
      currentMode() === "bits" ? derivedCharsDisplay : derivedBitsDisplay;
    if (!pw) {
      activeDisplay.textContent = "Generate a password first.";
      return;
    }
    const tableName = addTableSelect.value;
    if (!tableName) {
      activeDisplay.textContent = "Select a table first.";
      return;
    }
    const data = getTableData();
    if (!data) {
      activeDisplay.textContent = "Not logged in.";
      return;
    }
    const table = data.find((t) => t.name === tableName);
    if (!table) {
      activeDisplay.textContent = "Table not found.";
      return;
    }

    let col = table.columns.find((c) => c.type === "password");
    if (!col) {
      col = {
        id: crypto.randomUUID(),
        label: "Passwords",
        type: "password",
        data: [],
      };
      // Fill existing rows with defaults
      for (let i = 0; i < table.rowIds.length; i++) {
        col.data.push({ type: "password", value: "" });
      }
      table.columns.push(col);
    }
    if (col.type === "password") {
      const newRowId = crypto.randomUUID();
      table.rowIds.push(newRowId);
      col.data.push({ type: "password", value: pw });
      for (const c of table.columns) {
        if (c === col) continue;
        if (c.type === "textarea") c.data.push("");
        else if (c.type === "link") c.data.push({ url: "" });
        else if (c.type === "password")
          c.data.push({ type: "password", value: "" });
      }
    }
    activeDisplay.textContent = `Added to table "${tableName}".`;
  });

  return {
    clear(): void {
      passwordOutput.value = "";
      refreshTableSelect();
      updateDerivedDisplay();
    },
  };
}
