// Builds the Android app (android/): the web app and the autofill screen go in
// its assets, so the app runs the code shipped in the APK rather than code
// from the server. Run `npm run build:android` (it builds the wasm first);
// `-- --release` builds the release APK instead of the debug one. Needs
// JAVA_HOME (JDK 17 or later) and ANDROID_HOME, or android/local.properties.
//
// The pages get a Content Security Policy allowing only their own scripts
// (inline ones by hash), and no connections but to the app's own assets: what
// reaches the server goes through the app (see frontend/nativeApp.ts).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "android/app/build/web");
const release = process.argv.includes("--release");
const webOnly = process.argv.includes("--web-only");

await rm(out, { recursive: true, force: true });
execFileSync(
  "npx",
  [
    "parcel",
    "build",
    "frontend/index.html",
    "android/web/autofill.html",
    "--dist-dir",
    out,
    "--public-url",
    "./",
    "--no-source-maps",
  ],
  { cwd: root, stdio: "inherit" },
);

/** Every file under `dir`. */
async function walk(dir) {
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(path)));
    else files.push(path);
  }
  return files;
}

// Parcel puts the pages where their sources are, but links them as if they
// were next to the bundles
for (const [from, to] of [
  ["frontend/index.html", "index.html"],
  ["android/web/autofill.html", "autofill.html"],
])
  await rename(join(out, from), join(out, to));
await rm(join(out, "android"), { recursive: true });

for (const file of await walk(out)) {
  if (!file.endsWith(".html")) continue;
  const html = await readFile(file, "utf8");
  const hashes = [
    ...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([^<]*)<\/script>/g),
  ]
    .map(([, body]) => createHash("sha256").update(body).digest("base64"))
    .map((hash) => `'sha256-${hash}'`);
  const policy = [
    "default-src 'none'",
    `script-src 'self' 'wasm-unsafe-eval' ${hashes.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob: mediastream:",
    "font-src 'self'",
    "connect-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  // first, so it covers everything after it (the minifier leaves out <head>)
  const withPolicy = html.replace(
    /^(<!DOCTYPE html>)?/i,
    `$1<meta http-equiv=Content-Security-Policy content="${policy}">`,
  );
  await writeFile(file, withPolicy);
}
console.log(`Built the app's pages in ${out}`);

if (!webOnly)
  execFileSync(
    process.platform === "win32" ? "gradlew.bat" : "./gradlew",
    [release ? "assembleRelease" : "assembleDebug"],
    { cwd: join(root, "android"), stdio: "inherit" },
  );
