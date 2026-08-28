# Releasing

Distribution is prebuilt static binaries on a GitHub release. `publish = false`, so not
on crates.io. GitHub (`origin`) is canonical; the forgejo remote is a mirror.

## Cadence

A tag publishes binaries, so it is deliberate. Batch small non-surface changes (`plan`
and stderr wording, docs, tutorial, perf, internal refactors) into `[Unreleased]` and let
them accumulate. Do not cut a release candidate for each. Tag when a **promised surface**
moves (the JSONL record, the CLI, the config format; see `docs/stability.md`), or when
enough has accumulated to be worth a build, and only when asked. The rule exists because
rc.2 through rc.4 shipped on one day with one change each. Prefer one rc that carries the
batch.

## Checklist

1. **Changelog.** Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh
   `## [Unreleased]` above it. Without the fresh heading the next entry lands under the
   version just shipped.
2. **Bump `version` in `Cargo.toml`**, then `cargo build` so `Cargo.lock` follows. The
   release workflow refuses a tag that does not match `--version`.
3. **Regenerate `man/scanr.1`** with `cargo run --example gen_man`; the pages carry the
   version and `tests/man_pages.rs` fails when they are stale.
4. **Update the status line in `ROADMAP.md`** with the new rc and date.
5. **Commit with a clean tree.** `build.rs` stamps the commit into every record and marks
   a dirty tree `-dirty`; the workflow refuses a dirty binary.
6. **Verify locally.**

   ```console
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo deny check
   cargo build --release --target x86_64-unknown-linux-musl
   readelf -d target/x86_64-unknown-linux-musl/release/scanr | grep -c NEEDED   # 0
   ```

7. **Tag and push.**

   ```console
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main --follow-tags
   ```

   One tag per push. GitHub does not trigger `push` workflows for a push carrying more
   than three tags; releasing 0.3.0 through 1.0.0-rc.1 in one `--follow-tags` push ran
   CI and nothing else, and each tag had to be deleted and re-pushed on its own.

8. **Check the release.** All eight archives with `.sha256` files, notes from the
   changelog, and `scanr --version` inside a downloaded archive reporting the tag with
   no `-dirty` suffix.

## Workflows

`ci.yml` runs on every push and PR. It covers fmt, clippy `-D warnings`, tests on gnu and
musl, the musl binary checked for 0 `NEEDED` entries, macOS build and test, the nmap
differential, an 85 % region-coverage floor, MSRV (`rust-version` in `Cargo.toml`),
`cargo install` from a clean checkout, `cargo deny`, and a replay of `fuzz/seeds/`.

`release.yml` runs on a `v*` tag. It cross-compiles eight targets with `cargo-zigbuild`
(x86_64/aarch64/armv7/i686/riscv64gc/powerpc64le static musl, plus x86_64/aarch64
glibc). scanr is pure Rust with no C deps, so one toolchain covers them all without VMs.
Each build job checks the tag against `--version` and refuses a dirty tree or a binary
stamped `-dirty`. Completions are generated once, natively, into the ignored
`dist/completions` (an untracked `completions/` in the tree made rc.6 and rc.7 report
`-dirty`). Each archive packages the binary, README, changelog, licences and
completions; the `publish` job writes SHA-256 sums and attaches everything to the
release. Only `publish` has `contents: write`. `scripts/build-all.sh` runs the same
build locally. To add or drop a target, edit both the `release.yml` matrix and the
`TARGETS` list in the script.

Both workflows need `fetch-depth: 0` because `build.rs` reads git history.

The fuzz job replays committed seeds only. Fuzzing itself is manual:

```console
cargo +nightly fuzz run specs -- -max_total_time=600
```

A `cargo-fuzz` installed by `cargo binstall` is a musl build and defaults to the musl
target, where the sanitizer cannot link. Add `--target x86_64-unknown-linux-gnu`, or
install it from source (`cargo install cargo-fuzz --locked`, as CI does).

## Versioning

See `CHANGELOG.md` "About the version number" and `ROADMAP.md`. Pre-1.0, a
`schema_version` bump is a minor. From 1.0, a major.
