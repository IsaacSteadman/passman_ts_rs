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
