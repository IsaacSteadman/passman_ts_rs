#!/usr/bin/env bash
# Creates .patched-crates/<crate>-<version> from the published crate plus
# patches/<crate>-<version>.patch. Cargo.toml's [patch.crates-io] points at
# these directories, so this must run before any cargo command.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$root/.patched-crates"

# name version sha256-of-published-.crate (same as Cargo.lock's checksum before patching)
crates=(
  "tokio 1.48.0 ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408"
)

for entry in "${crates[@]}"; do
  read -r name version sha256 <<<"$entry"
  dest="$out_dir/$name-$version"
  patch_file="$root/patches/$name-$version.patch"
  stamp="$(sha256sum "$patch_file" | cut -d' ' -f1)"

  if [[ -f "$dest/.patch-stamp" && "$(cat "$dest/.patch-stamp")" == "$stamp" ]]; then
    continue
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "https://static.crates.io/crates/$name/$name-$version.crate" -o "$tmp/crate.tar.gz"
  echo "$sha256  $tmp/crate.tar.gz" | sha256sum --check --quiet
  tar xzf "$tmp/crate.tar.gz" -C "$tmp"
  patch --quiet --forward -p1 -d "$tmp/$name-$version" <"$patch_file"
  echo "$stamp" >"$tmp/$name-$version/.patch-stamp"

  mkdir -p "$out_dir"
  rm -rf "$dest"
  mv "$tmp/$name-$version" "$dest"
  rm -rf "$tmp"
  trap - EXIT
  echo "patched $name $version"
done
