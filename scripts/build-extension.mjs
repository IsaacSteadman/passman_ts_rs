// Builds the browser extensions (extension/) into dist-extension/:
//   chromium/  Chrome, Edge, Brave, … (and passman-chromium.zip)
//   firefox/   Firefox (and passman-firefox.zip)
//   safari/    Safari; on a Mac, `scripts/package-safari.sh` wraps it in the
//              Xcode project Safari extensions need
// Run `npm run build:extension` (it builds the wasm first). With `--test` it
// also builds chromium-test/, which may reach every site without asking, for
// the Playwright tests.
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist-extension");
const build = join(out, "build");
const { version } = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);

await rm(out, { recursive: true, force: true });
// Built together: with only HTML entries Parcel would put an inline import
// map in popup.html, which extension pages' CSP doesn't run
execFileSync(
  "npx",
  [
    "parcel",
    "build",
    "extension/popup.html",
    "extension/background.ts",
    "--dist-dir",
    build,
    "--public-url",
    "./",
    "--no-source-maps",
  ],
  { cwd: root, stdio: "inherit" },
);
// the background script must be one file, as the manifest names only it
const files = await readdir(build);
if (
  files.some(
    (f) => f.endsWith(".js") && !/^(popup\.[0-9a-f]+|background)\.js$/.test(f),
  )
)
  throw new Error(`unexpected bundles: ${files.join(", ")}`);
// the popup's script carries its own copy of the import map, which CSP would
// block inline anyway
const popupHtml = join(build, "popup.html");
await writeFile(
  popupHtml,
  (await readFile(popupHtml, "utf8")).replace(
    /<script type=importmap>[^<]*<\/script>/,
    "",
  ),
);

const icons = Object.fromEntries(
  [16, 32, 48, 128].map((size) => [size, `icons/icon-${size}.png`]),
);

/** What all three browsers share. */
const base = {
  manifest_version: 3,
  name: "Firaxite Password Manager",
  short_name: "Passman",
  version,
  description: "Fills in logins from your Passman vault.",
  icons,
  action: {
    default_popup: "popup.html",
    default_title: "Passman",
    default_icon: { 16: icons[16], 32: icons[32] },
  },
  // the page in the current tab is only touched when the user opens the
  // popup there (activeTab); the server is asked for when unlocking
  permissions: ["storage", "activeTab", "scripting", "alarms", "idle"],
  optional_host_permissions: ["https://*/*", "http://*/*"],
  content_security_policy: {
    extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
  },
  commands: {
    _execute_action: {
      suggested_key: { default: "Alt+Shift+P" },
      description: "Open Passman",
    },
  },
};

const manifests = {
  chromium: {
    ...base,
    minimum_chrome_version: "120",
    background: { service_worker: "background.js" },
  },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: {
      gecko: {
        id: "passman@firaxite.com",
        strict_min_version: "140.0",
        data_collection_permissions: { required: ["none"] },
      },
      gecko_android: { strict_min_version: "142.0" },
    },
  },
  safari: {
    ...base,
    // Safari has no idle API
    permissions: base.permissions.filter((p) => p !== "idle"),
    background: { service_worker: "background.js" },
  },
};
if (process.argv.includes("--test"))
  manifests["chromium-test"] = {
    ...manifests.chromium,
    host_permissions: ["<all_urls>"],
  };

for (const [browser, manifest] of Object.entries(manifests)) {
  const dir = join(out, browser);
  await cp(build, dir, { recursive: true });
  await mkdir(join(dir, "icons"), { recursive: true });
  await cp(join(root, "extension/icons"), join(dir, "icons"), {
    recursive: true,
  });
  await writeFile(
    join(dir, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  if (browser === "chromium" || browser === "firefox")
    execFileSync("zip", ["-qr", join(out, `passman-${browser}.zip`), "."], {
      cwd: dir,
    });
}
await rm(build, { recursive: true });
console.log(`Built the extensions in ${out}`);
