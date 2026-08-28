# Stability

What 1.x promises, and what it does not. Effective from `1.0.0`; `1.0.0-rc.N` builds carry
the same surface so the promise can soak before it is made.

## Promised surfaces

| surface | promise within 1.x | held to it by |
|---|---|---|
| **JSONL record** | Additive only. New optional fields and new event types may appear. Existing fields keep their type and meaning and are not removed. `state` and `source` are closed sets. Every `schema_version` this major has written stays readable by every later 1.x. | `tests/spec_conformance.rs`, `tests/compat.rs` |
| **CLI** | Commands, flags, exit codes, and the shape of stdout formats (`table`, `json`, `nmap`, `list`) are stable. Removing or renaming any of them needs a deprecation warning for at least one minor first (`--json` on `output summarize` is the worked example). | `tests/cli_spec.rs`, `tests/man_pages.rs` |
| **Config** | Every key and its meaning is stable; new keys are additive; unknown keys stay errors. A `scanr.toml` that validated under any 1.x validates under every later 1.x. | `config init` drift guards in `src/config/builtin.rs`, `tests/compat.rs` |

A `schema_version` bump, a closed set widened, a flag removed without its deprecation
period, or a config key's meaning changed is a **major** version.

## Not promised

- The library API. `lib.rs` says so; every module is public only so tests and fuzz targets can reach it.
- stderr text, `plan` rendering, progress lines, warning wording. Match on `scan_warning.code`, not on prose.
- Performance figures. They are measurements on one machine, recorded with their method.
- Platforms. **Linux x86_64 (gnu and musl) is the tested platform** — the full suite runs
  there in CI. Release binaries are also cross-compiled for aarch64, armv7, i686, riscv64
  and ppc64le (static musl) and for aarch64 (glibc); those are built and
  smoke-run under emulation, not full-tested, and are provided best-effort. macOS builds
  and passes CI as a courtesy; Windows is not planned.
- MSRV. A bump is a minor.
- Per-proxy behaviour. What a given proxy answers is measured, not promised; `transport test` measures yours.

## Deprecation

A deprecated flag or key keeps working for at least one minor, warns on stderr every time
it is used, is listed in `CHANGELOG.md` under `Deprecated`, and is removed in a major.

## Reading old records

`scanr output …` reads every `schema_version` this major has written; `verify` names the
versions it accepts. `tests/compat/` holds a record from each schema version and the
exact output every reader must still produce for it.
