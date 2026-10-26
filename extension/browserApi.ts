// The extension APIs: `browser` in Firefox and Safari, `chrome` in Chromium.
// All of them return promises in Manifest V3.

declare const browser: typeof chrome | undefined;

export const ext: typeof chrome =
  typeof browser !== "undefined" ? browser : chrome;
