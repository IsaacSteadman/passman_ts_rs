# passman_ts_rs

## Building

This project builds against a patched tokio (adds `RwLock::upgrade`, see
`patches/tokio-1.48.0.patch`). Before running any `cargo` command on a fresh
checkout, and after the patch changes, run:

```sh
./scripts/patch-crates.sh
```

It downloads the published crate, verifies its SHA-256, applies the patch and
writes the result to `.patched-crates/` (gitignored), where
`[patch.crates-io]` in `Cargo.toml` points.

## Running the server

The server reads `config.json` and `policies.json` from `CARGO_MANIFEST_DIR`
and keeps its data in `server_data/` there. It listens on `127.0.0.1`, on the
port in the `PORT` environment variable (which the deployment sets), else
`Port` in `config.json` (8080 by default), behind a reverse proxy that
terminates TLS and passes the client's address in `X-Real-IP`.

`config.json`:

| Field                    | Default  | Meaning                                                                 |
| ------------------------ | -------- | ----------------------------------------------------------------------- |
| `ServerAccessPassword`   | required | unlimited access (accounts, shared vaults)                              |
| `Port`                   | `8080`   | when `PORT` isn't set                                                   |
| `MaxBufferedUploadBytes` | 256 MiB  | shared vault uploads held in memory at once (more are refused with 503) |
| `RateLimit`              | below    | request rates, bans and throttling                                      |

**Rate limiting.** Each client IP (an IPv6 /64 counts as one) may make
`RequestsPerSecond` requests (20) with bursts of `RequestBurst` (200). Failed
logins (a wrong server or policy password, or a wrong account password)
count against the IP: after `BadIpFailures` (3) within `FailureWindowSecs`
(15 min) it is a "bad" IP, and after `FailuresToBan` (10) it is banned for
`BanSecs` (15 min), twice as long each further time within a day, up to
`MaxBanSecs` (24 h). An account with `AccountFailuresToThrottle` (5) failures
from anywhere is throttled until a window passes without failures: an IP
that hasn't logged into it in the last `TrustedIpDays` (30) waits
`AccountDelaysSecs` (1, 5, 10, 30, then 60 s) before each attempt at it, twice
as long if it's a bad IP, whose failures there then count double. The account
is never locked, so its owner always gets in after a short wait (the apps
wait by themselves), and at once from where they logged in before. Every
table is bounded (`MaxTrackedIps`, `MaxTrackedAccounts`, `MaxIpsPerAccount`).
`"RateLimit": {"Enabled": false}` turns it off, for local testing only.

**Web app headers.** Pages get a Content Security Policy allowing only the
app's own scripts and styles (and, by hash, the page's own inline ones),
WebAssembly, and no framing; every response gets `nosniff` and no referrer.
The web app is served by the server it talks to, so it can't protect against
a compromised server the way the extension and the Android app (whose code
comes with them) do.

## Accounts and keys

An account's keys are derived in the browser from its username and password:
one Argon2id (64 MiB, 3 passes) of the password, salted with the username and
an app-wide salt, split with HKDF into an auth key and an encryption key. The
server only sees the auth key, and stores its SHA-512 (a slow hash would add
nothing: the encrypted vault stored next to it can be attacked at one Argon2id
per guess anyway, and it would let anyone with the server password load the
server). The vault is encrypted with XChaCha20-Poly1305 and carries a revision
number, so a device that has seen a version refuses an older one from the
server.

## Browser extensions

`extension/` holds extensions for Chromium browsers (Chrome, Edge, Brave, …),
Firefox and Safari. `npm run build:extension` builds them into
`dist-extension/`: `chromium/` and `firefox/` (also zipped, for the Chrome Web
Store and addons.mozilla.org) and `safari/`, which `scripts/package-safari.sh`
wraps in the Xcode project Safari needs (on a Mac). To try one, load the
folder unpacked: `chrome://extensions` → Developer mode → Load unpacked, or
`about:debugging` → This Firefox → Load Temporary Add-on (pick
`manifest.json`).

The popup unlocks the account on the user's Passman server (asking for
permission to reach that server), then:

- lists the logins for the current tab's site (a row with a link to that
  site, or a subdomain of it, and a username, password or MFA key), from the
  user's own vault and from shared vaults, which it checks as the web app
  does (and marks when a manager isn't verified);
- fills them into the page, only on their own site and never from an https
  login into an http page, and fills or copies MFA codes;
- finds any login by searching (copying only: filling elsewhere could hand a
  password to a lookalike site);
- saves what was typed on the page, or a generated password, as a new login
  in the user's own vault, or as the new password of the saved login with
  that username.

The page is only touched when the user opens the popup on it (`activeTab`),
so the extension doesn't need access to every site. The unlocked session is
kept in the browser's session storage (in memory) until the browser closes,
the computer is locked, or it goes unused for the time chosen in the popup
(15 minutes unless changed). Open the popup with Alt+Shift+P.

## Android app

`android/` is an Android app (Android 11 and later) with the web app inside,
plus what a web page can't do. `npm run build:android` builds the debug APK
(`android/app/build/outputs/apk/debug/`); `npm run build:android -- --release`
the release one, signed if `android/keystore.properties` names a keystore
(`storeFile`, `storePassword`, `keyAlias`, `keyPassword`). It needs JDK 17 or
later (`JAVA_HOME`) and the Android SDK (`ANDROID_HOME`, or `sdk.dir` in
`android/local.properties`). On first start the app asks for the server's
address.

- **The code comes with the app.** The pages are in the APK, not loaded from
  the server, so whoever controls the server (or its certificate) can't serve
  a page that sends away passwords. The web view may load nothing but those
  pages; a Content Security Policy limits them to their own scripts, and
  they reach the network only through the app, which sends requests to the
  server alone (`frontend/nativeApp.ts`).
- **Certificate pinning (optional).** When choosing the server, the app shows
  its certificate key, and can trust only that key from then on. Only the
  certificate authorities that come with Android are trusted, not ones a user
  or device profile installed; plain HTTP isn't allowed (except to a
  development server in debug builds).
- **Biometric unlock with the Android Keystore.** The account's keys are
  encrypted with an AES key in StrongBox (or the TEE) that can't be read out,
  can only be used right after a strong biometric check, only while the
  device is unlocked, and is deleted by Android when fingerprints or faces are
  added or removed. Unlike the web app's passkeys, it is never synced.
- **Autofill.** Passman can be Android's autofill service ("Fill with
  Passman" in apps' and browsers' login forms). The vault is only unlocked
  after the user picks it, on Passman's own screen. A browser's word for which
  site is open is only taken from known browsers, checked by signing
  certificate (`scripts/update-browsers.mjs`); apps are identified by package
  name and signing certificate, saved as `android://<hash>@<package>/` links,
  so a lookalike app gets nothing. Linking an existing login to an app asks
  first, saying whether the login's site lists the app as its own (Digital
  Asset Links). After a form is sent, Passman offers to save what was typed.
- **The screen.** No screenshots or screen recording of Passman, a blank
  thumbnail in recent apps, and no other app's windows over it. Keyboards
  are asked not to learn from what's typed.
- **Clipboard.** Copied passwords and codes are marked sensitive (hidden from
  the clipboard preview) and cleared after 45 seconds.
- **No backups.** Nothing of Passman's goes into Android backups or
  device-to-device transfers.

`tests/android.spec.ts` runs on an emulator or device (and is skipped without
one). It needs a screen lock and an enrolled fingerprint, which the tests
present with `adb emu finger touch 1`, and the server on this computer
(reached as `10.0.2.2:8080`). `android/demo` is a separate app with a login
form for trying autofill.

## Shared vaults

Users can share vaults with each other. The server only stores ciphertext and
signed data, and isn't trusted with who may do what: members' browsers check
everything they download (the server checks the same things, with the same
code in `passman_crypto/src/sharing.rs`, before storing it).

- **Identities.** Setting up sharing creates an identity, kept in the user's
  own vault: Ed25519 + ML-DSA-65 signing keys (both must sign) and an X-Wing
  (X25519 + ML-KEM-768) key for receiving vault keys. Its public half is
  published on the server.
- **Verification.** Before adding someone, a member verifies their identity's
  fingerprint: in person by scanning each other's QR codes (which hold only the
  username and fingerprint), or by reading a safety number to each other on a
  call. Vaults managed by someone the user hasn't verified carry a warning.
- **Invitations.** Anyone can add a user to a vault, so it first shows as an
  invitation (who added them, the members and whether they're verified), and
  isn't used anywhere (in the vault list, the extension or autofill) until
  they accept it, which needs the inviter to be verified. Accepting is
  recorded in the user's own vault, so the server can't accept for them.
  Declining is leaving.
- **Member lists** are a chain of records, each signed by a member who could
  manage members in the previous one (and who stays in it). Every record
  starts an epoch with a new random key, wrapped for each member, so removed
  members can't read anything saved afterwards and new members can't read
  anything saved before. Members can edit or only read, and can manage
  members or not. The server keeps a vault's latest records only; a device
  without the older ones checks the chain from the oldest kept, which, like a
  vault's first record, is trusted on first sight.
- **Leaving.** A member leaves (or declines) with a statement they sign, or
  a manager signs one for them; it's only valid in the epoch it was made in.
  The server stops serving them the vault at once, and a manager's browser
  removes them (with a new key) once it has checked the statement, so the
  server can't get anyone removed on its own.
- **Versions** of a vault are signed by their author, who must be allowed to
  edit. Each epoch's history is kept separately (encrypted with that epoch's
  key), so members only see the history from when they joined. Members who
  can edit can delete entries from the current epoch's history (as anyone
  can from their own vault's), but not from past epochs'.
- **Size.** What counts toward a vault's size is its encrypted tables and
  history, including past epochs' (not the signatures around them). To fit,
  the server drops the oldest past epochs' history first, then the app drops
  the oldest entries of the current history, down to the vault's minimum
  (a setting in the vault); the app warns before either happens, and before a
  save that would still be too large (and so is refused).
- **Offline.** For accounts remembered on the device, shared vaults are kept
  there too and can be changed offline; changes are saved when back online,
  as long as the user can still edit the vault (otherwise they can be copied
  to their own vault). A device that has a vault refuses an older member list
  or version from the server.

A `LIMITED_POLICY` in `policies.json` limits shared vaults separately from
accounts. A vault's limits are those of the policy it was created under, set
when it's created and kept with it, whichever credentials its members use:

| Field                    | Default   | Meaning                                                                        |
| ------------------------ | --------- | ------------------------------------------------------------------------------ |
| `MaxSharedVaultsPerUser` | `4`       | shared vaults each user may create (counted until deleted, even if they leave) |
| `MaxSharedVaults`        | unlimited | shared vaults under the policy in all                                          |
| `NumSharedVaults`        | `0`       | maintained by the server                                                       |
| `MaxSharedVaultDataSize` | 16 KiB    | encrypted contents (tables and history) per shared vault                       |
| `MaxSharedVaultMembers`  | `8`       | members per shared vault                                                       |
| `MaxSharedVaultRecords`  | `16`      | member list records kept per vault (older ones go, with their history)         |

The server access password and `ROOT_POLICY` have no limits but the server's
own (64 MiB, 256 members, 64 records); a `NULL_POLICY` (or a removed policy)
leaves its shared vaults readable (and leavable) but not changeable. Shared
vault data lives in `server_data/.shared/`; identity bundles are kept only
while they're someone's current identity or named in a record kept.
