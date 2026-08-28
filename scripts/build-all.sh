#!/usr/bin/env bash
# Cross-compile scanr for every supported target and package each as a
# `.tar.gz` + `.sha256` under `dist/`. Pure-Rust, no C deps, so one toolchain
# (cargo-zigbuild, which carries its own cross linker and libc) covers them all —
# no VMs, no per-target sysroots.
#
#   scripts/build-all.sh [VERSION]
#
# Needs: rustup, zig, cargo-zigbuild. Install the cross tooling with:
#   rustup target add <target>            # once per target (see TARGETS below)
#   cargo binstall cargo-zigbuild         # or: cargo install cargo-zigbuild
#   # zig: your package manager, or `pip install ziglang`
set -euo pipefail

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Static musl (drop it on anything) first, then the glibc-only architectures.
TARGETS=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  armv7-unknown-linux-musleabihf
  i686-unknown-linux-musl
  riscv64gc-unknown-linux-musl
  powerpc64le-unknown-linux-musl
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
)

command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild not found" >&2; exit 1; }

# Shell completions are identical for every target, so generate them once from a
# native build rather than trying to run each cross binary.
echo ">> completions (native)"
cargo build --release --quiet
mkdir -p dist/completions
for sh in bash zsh fish elvish power-shell; do
  target/release/scanr completion "$sh" > "dist/completions/$sh"
done

for t in "${TARGETS[@]}"; do
  echo ">> $t"
  rustup target add "$t" >/dev/null 2>&1 || true
  cargo zigbuild --release --locked --target "$t"
  name="scanr-${VERSION}-${t}"
  stage="dist/$name"
  mkdir -p "$stage/completions"
  cp "target/$t/release/scanr" "$stage/"
  cp README.md CHANGELOG.md LICENSE-MIT LICENSE-APACHE "$stage/"
  cp dist/completions/* "$stage/completions/"
  tar -C dist -czf "dist/$name.tar.gz" "$name"
  ( cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
  rm -rf "$stage"
done

echo
echo "built ${#TARGETS[@]} targets into dist/:"
ls -1 dist/*.tar.gz
