# Releasing

Distribution is prebuilt static binaries on a GitHub release. `publish = false`: not on
crates.io. GitHub (`origin`) is canonical; the forgejo remote is a mirror.

## Cadence

A tag publishes binaries, so it is deliberate. Batch small non-surface changes — `plan`
and stderr wording, docs, tutorial, perf, internal refactors — into `[Unreleased]` and
let them accumulate; do not cut a release candidate for each. Tag when a **promised
surface** moves (the JSONL record, the CLI, the config format — see `docs/stability.md`),
or when enough has accumulated to be worth a build, and only when asked. rc.2 through rc.4
all shipped on one day, one change each; rc.4 was a `plan`-rendering polish that did not
touch a promised surface. Prefer one rc that carries the batch.

## Checklist

1. **Changelog.** Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh
   `## [Unreleased]` above it. Without the fresh heading the next entry lands under the
   version just shipped; that has happened twice.
2. **Bump `version` in `Cargo.toml`**, then `cargo build` so `Cargo.lock` follows. The
   release workflow refuses a tag that does not match `--version`.
3. **Commit with a clean tree.** `build.rs` stamps the commit into every record and marks
   a dirty tree `-dirty`; the workflow refuses a dirty binary.
4. **Verify locally.**

   ```console
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo deny check
   cargo build --release --target x86_64-unknown-linux-musl
   readelf -d target/x86_64-unknown-linux-musl/release/scanr | grep -c NEEDED   # 0
   ```

5. **Tag and push.**

   ```console
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main --follow-tags
   ```

   One tag per push. GitHub does not trigger `push` workflows for a push carrying more
   than three tags: releasing 0.3.0 through 1.0.0-rc.1 in one `--follow-tags` push ran
   CI and nothing else, and each tag had to be deleted and re-pushed on its own.

6. **Check the release:** both archives with `.sha256` files, notes from the changelog,
   `scanr --version` inside the archive reporting the tag.

## Workflows

`ci.yml` on every push and PR: fmt, clippy `-D warnings`, tests on gnu and musl, the musl
binary checked for 0 `NEEDED` entries, macOS build and test, the nmap differential, an 85 %
region-coverage floor, MSRV (`rust-version` in `Cargo.toml`), `cargo install` from a clean
checkout, `cargo deny`, and a replay of `fuzz/seeds/`.

`release.yml` cross-compiles nine targets with `cargo-zigbuild` (x86_64/aarch64/armv7/
i686/riscv64/ppc64le static musl, plus aarch64/s390x glibc) — scanr is pure Rust with no
C deps, so one toolchain covers them all, no VMs. `scripts/build-all.sh` runs the same
build locally and has produced all nine archives; the CI legs are newer than the local
path, so expect to iterate on the first real tag. To add or drop a target, edit both the
`release.yml` matrix and the `TARGETS` list in the script.

The fuzz job replays committed seeds only. Fuzzing itself is manual:

```console
cargo +nightly fuzz run specs -- -max_total_time=600
```

A `cargo-fuzz` installed by `cargo binstall` is a musl build and defaults to the musl
target, where the sanitizer cannot link; add `--target x86_64-unknown-linux-gnu`, or
install it from source (`cargo install cargo-fuzz --locked`, as CI does).

`release.yml` on a `v*` tag: builds both targets, checks tag versus `--version` and a
clean tree, packages README, changelog, licences and completions, writes SHA-256 sums,
attaches everything to the release. Only the `publish` job has `contents: write`.

Both need `fetch-depth: 0`: `build.rs` reads git history.

## Versioning

See `CHANGELOG.md` "About the version number" and `ROADMAP.md`. Pre-1.0: a
`schema_version` bump is a minor. From 1.0: a major.
