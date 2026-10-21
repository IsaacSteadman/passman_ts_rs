// Light or dark appearance. "auto" follows the device's setting. The choice
// belongs to this device: it's kept in localStorage and never synced with the
// account. The colours themselves are in theme.less.

export type ThemeChoice = "auto" | "light" | "dark";

// Also read by the script in index.html's <head>, which applies the theme
// before the page is first drawn.
const STORAGE_KEY = "passman.theme";

/** Colour of the browser / system bars around the app, per theme. */
const BAR_COLORS = { light: "#ffffff", dark: "#1f2937" } as const;

export function loadTheme(): ThemeChoice {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // storage unavailable: follow the device
  }
  return "auto";
}

export function saveTheme(choice: ThemeChoice): void {
  if (choice === "auto") localStorage.removeItem(STORAGE_KEY);
  else localStorage.setItem(STORAGE_KEY, choice);
  applyTheme(choice);
}

export function applyTheme(choice: ThemeChoice = loadTheme()): void {
  const root = document.documentElement;
  if (choice === "auto") delete root.dataset.theme;
  else root.dataset.theme = choice;
  // one tag per device scheme; a chosen theme overrides both
  for (const meta of document.querySelectorAll<HTMLMetaElement>(
    "meta[name='theme-color'][data-scheme]",
  )) {
    const scheme = meta.dataset.scheme === "dark" ? "dark" : "light";
    meta.content = BAR_COLORS[choice === "auto" ? scheme : choice];
  }
}

/** Applies the saved theme now and whenever another window changes it. */
export function initTheme(): void {
  applyTheme();
  window.addEventListener("storage", (event) => {
    if (event.key === STORAGE_KEY || event.key === null) applyTheme();
  });
}
