// Updates android/app/src/main/res/raw/browsers.json: the browsers whose word
// the Android app's autofill takes for which site a login form is on, by
// package name and release signing certificate. From the list Google keeps of
// browsers privileged for passkeys and passwords.
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json";
const out = join(
  dirname(fileURLToPath(import.meta.url)),
  "../android/app/src/main/res/raw/browsers.json",
);

const response = await fetch(SOURCE);
if (!response.ok) throw new Error(`${SOURCE}: ${response.status}`);
const { apps } = await response.json();
const browsers = {};
for (const app of apps) {
  if (app.type !== "android") continue;
  const fingerprints = app.info.signatures
    .filter((s) => s.build === "release")
    .map((s) => s.cert_fingerprint_sha256.toUpperCase());
  if (fingerprints.length > 0)
    browsers[app.info.package_name] = [
      ...(browsers[app.info.package_name] ?? []),
      ...fingerprints,
    ];
}
await writeFile(out, `${JSON.stringify(browsers, null, 1)}\n`);
console.log(`${Object.keys(browsers).length} browsers in ${out}`);
