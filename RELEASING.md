# Releasing

Distribution is prebuilt static binaries attached to a GitHub release. The crate is
marked `publish = false` and is not pushed to crates.io; remove that line if that ever
changes.

> The workflows in `.github/workflows/` were written without a remote to run them
> against and are therefore **unverified**. Expect to iterate on the first push and the
> first tag. Everything below has been checked locally except the workflow runs
> themselves.

## Checklist

1. **Move the changelog section.** `CHANGELOG.md` accumulates under `## [Unreleased]`.
   Rename it to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above.

   This is not cosmetic. The release workflow extracts the section whose heading matches
   the tag and uses it as the release notes; leaving everything under `Unreleased`
   produces an empty body and a warning.

2. **Bump `version` in `Cargo.toml`** and run `cargo build` so `Cargo.lock` updates.

   The release workflow refuses to publish if the tag does not match what the binary
   reports, so a forgotten bump fails the build rather than shipping a mislabelled
   artifact.

3. **Commit with a clean tree.** `build.rs` stamps the commit into every scan record and
   marks a dirty tree with a `-dirty` suffix. The release workflow refuses to publish a
   binary that advertises `dirty`, because a record that cannot be traced to a commit
   defeats the point of the record.

4. **Verify locally.**

   ```console
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo deny check
   cargo build --release --target x86_64-unknown-linux-musl
   ldd target/x86_64-unknown-linux-musl/release/scanr   # "not a dynamic executable"
   ```

5. **Tag and push.**

   ```console
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin master --follow-tags
   ```

6. **Check the release.** Both archives present with `.sha256` files, notes populated
   from the changelog, and `scanr --version` inside the archive reporting the tag.

## What the workflows do

`ci.yml` runs on every push and pull request: formatting, clippy with warnings as
errors, tests on both glibc and static musl, an MSRV job pinned to the `rust-version` in
`Cargo.toml`, `cargo install` from a clean checkout, `cargo deny`, and a replay of the
committed fuzz seeds.

The fuzz job replays `fuzz/seeds/` only — it is a regression check, not a fuzzing run.
It pins the two crashes fuzzing has already found. Real fuzzing is a manual activity:

```console
cargo +nightly fuzz run specs -- -max_total_time=600
```

`release.yml` runs on a `v*` tag: builds both targets, verifies the tag matches the
binary and that the tree was clean, packages each with the README, changelog, both
licences and shell completions, generates SHA-256 sums, and attaches everything to the
release.

Both need `fetch-depth: 0`, because `build.rs` reads git history.

## Versioning

`scanr` is at `0.x` deliberately. The JSONL record is additive-stable within
`schema_version 1`, but that is not yet hardened into a semver `1.0` commitment — see the
note at the top of `CHANGELOG.md`. `1.0.0` is reserved until an external consumer has
parsed a record and said what the format is missing.
