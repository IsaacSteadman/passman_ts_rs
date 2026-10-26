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

Users can share vaults with each other. The server only stores ciphertext:
each shared vault has its own random key, stored once per member sealed to
that member's sharing key (an X25519 public key; the secret key is kept in
the member's own vault). Members should compare sharing key fingerprints out
of band when adding someone, since the server hands out the public keys.

A `LIMITED_POLICY` in `policies.json` limits shared vaults separately from
accounts; the limits of the policy a vault was created under apply to it,
whichever credentials its members use:

| Field                    | Default         | Meaning                                           |
| ------------------------ | --------------- | ------------------------------------------------- |
| `MaxSharedVaults`        | `0`             | shared vaults that can be created (none if unset) |
| `NumSharedVaults`        | `0`             | maintained by the server                          |
| `MaxSharedVaultDataSize` | `MaxDataSize`   | size limit of each shared vault, in bytes         |
| `MaxSharedVaultMembers`  | unlimited (256) | members per shared vault                          |

The server access password and `ROOT_POLICY` have no limits; a `NULL_POLICY`
(or a removed policy) leaves its shared vaults readable but not changeable.
Shared vault data lives in `server_data/.shared/`.
