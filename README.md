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
- **Member lists** are a chain of records, each signed by a member who could
  manage members in the previous one. Every record starts an epoch with a new
  random key, wrapped for each member, so removed members can't read anything
  saved afterwards and new members can't read anything saved before. Members
  can edit or only read, and can manage members or not.
- **Versions** of a vault are signed by their author, who must be allowed to
  edit. Each epoch's history is kept separately (encrypted with that epoch's
  key), so members only see the history from when they joined.
- **Offline.** For accounts remembered on the device, shared vaults are kept
  there too and can be changed offline; changes are saved when back online,
  as long as the user can still edit the vault (otherwise they can be copied
  to their own vault).

A `LIMITED_POLICY` in `policies.json` limits shared vaults separately from
accounts; the limits of the policy a vault was created under apply to it,
whichever credentials its members use:

| Field                    | Default         | Meaning                                                          |
| ------------------------ | --------------- | ---------------------------------------------------------------- |
| `MaxSharedVaults`        | `0`             | shared vaults that can be created (none if unset)                |
| `NumSharedVaults`        | `0`             | maintained by the server                                         |
| `MaxSharedVaultDataSize` | `MaxDataSize`   | bytes per shared vault (older epochs' history is dropped to fit) |
| `MaxSharedVaultMembers`  | unlimited (256) | members per shared vault                                         |

The server access password and `ROOT_POLICY` have no limits; a `NULL_POLICY`
(or a removed policy) leaves its shared vaults readable but not changeable.
Shared vault data lives in `server_data/.shared/`.
