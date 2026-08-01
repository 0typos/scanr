# TOML Configuration Specification

## Discovery and precedence

Two files, both optional, project wins (D13):

1. `~/.config/scanr/config.toml` (or `$XDG_CONFIG_HOME/scanr/config.toml`)
2. `./scanr.toml`, searched upward from cwd to the filesystem root

`--config <path>` replaces both. `scanr config path` prints what was found.

Resolution order, lowest to highest:

```
compiled defaults
  → built-in profile
  → user config
  → project config
  → selected profile (--profile or scan.profile)
  → named scan definition
  → environment (credentials only)
  → CLI overrides (allowlist, see 06-cli-spec.md)
```

Every resolved field retains its source. `scanr plan` prints provenance.

Merge is **per-key**, not per-table: project config overriding one field of
`[profiles.proxy]` leaves the rest intact. Arrays replace wholesale rather than
concatenating — appending is never what you want for a target list you are trying to
control.

## Schema

```toml
version = 1                       # required; refuses to load unknown majors

[defaults]
# profile is optional: unset, it follows the transport (proxy for socks5, direct
# otherwise), so a direct ad-hoc scan does not inherit the proxy rate limit.
transport = "direct"
output_dir = "./scanr-results"
open_only = true                  # stdout only; JSONL always records everything

# Port labels, ahead of /etc/services and the builtin table. Optional; `~` expands.
# An /etc/services-format file: `name port/proto [aliases...]`, `#` comments.
services_file = "~/.config/scanr/services"
use_etc_services = true           # false: labels depend only on this config + the binary

# ── Profiles ────────────────────────────────────────────────────────
# Flat and complete. No inheritance (D-register: rejected for v1).
[profiles.proxy]
concurrency           = 512       # in-flight probes; = worker thread count
rate                  = 400       # probes/sec ceiling, 0 = unlimited
proxy_connect_timeout = "3s"
handshake_timeout     = "5s"
connect_timeout       = "5s"
retries               = 1         # timeouts only (D10)
retry_delay           = "250ms"

# ── Transports ──────────────────────────────────────────────────────
[transports.direct]
type = "direct"

[transports.lab]
type         = "socks5"
address      = "127.0.0.1:1080"
username     = "scanner"
password_env = "SCANR_LAB_PASSWORD"   # or password_file; inline `password` is an error (D14)
dns          = "auto"                 # auto | transport | local | disabled (D15)
fidelity     = "full"                 # full | open_only, as measured by `transport test` (D8)

# ── Target sets ─────────────────────────────────────────────────────
[targets.lab]
include = ["10.20.30.0/24", "10.20.31.10-10.20.31.20", "app.internal"]
exclude = ["10.20.30.1", "10.20.30.254"]

[targets.from-inventory]
file = "hosts.txt"                # one target per line, # comments, blank lines skipped

# ── Port sets ───────────────────────────────────────────────────────
[ports.web]
ports = ["80", "443", "8000-8999"]

# ── Named scans ─────────────────────────────────────────────────────
[scans.internal-web]
description = "Internal web services through the lab proxy"
profile     = "proxy"
transport   = "lab"
targets     = ["lab"]
ports       = ["web"]
# any profile field may be overridden inline:
connect_timeout = "8s"
```

Renamed from the original brief: `target_groups` → `targets`, `port_groups` → `ports`.
Shorter, and the plural key already reads as a set.

## Built-in profiles

Four, all fully explicit, no hidden behaviour:

| Profile | concurrency | rate | connect_timeout | retries | For |
|---|---|---|---|---|---|
| `proxy-careful` | 64 | 50 | 8s | 1 | Rotating pools, `ssh -D`, unknown limits |
| `proxy` | 512 | 400 | 5s | 1 | Self-hosted dante/microsocks (default for socks5 transports) |
| `direct` | 512 | 0 | 2s | 1 | Routed networks, no proxy (default for direct transports) |
| `direct-fast` | 2048 | 0 | 1s | 0 | LAN, latency known low |

`proxy` and `proxy-careful` default `rate` below the ~470/sec ephemeral ceiling for
remote proxies (D9). `plan` warns if a chosen rate exceeds what the ephemeral budget
supports.

## Targets

Accepted forms: IPv4/IPv6 literal · IPv4 CIDR · IPv6 CIDR · inclusive `a-b` range ·
hostname · `-` for stdin · `file = ` for a line-delimited file.

- IPv6 prefixes shorter than `/112` (65,536 addresses) are refused without
  `--allow-large-range`.
- Network and broadcast addresses of an IPv4 CIDR are included; nmap does the same and
  excluding them surprises people.
- Overlapping includes are de-duplicated. `exclude` is applied after expansion.
- Hostnames are permitted only when the effective DNS mode is not `disabled`.

## Ports

`80` · `1-1024` · `80,443,8080` · `all` (1-65535). Named sets referenced by
`ports = ["web"]`. Duplicates de-duplicated; the resolved plan records the canonical
sorted set and its count.

## Credentials

`password_env` names an environment variable. `password_file` names a file, which must
be mode `0600` or narrower or loading fails. Inline `password` is a hard validation
error naming both alternatives (D14).

Credentials are redacted in every output path: `plan`, `config show`, the JSONL
`scan_config` event, and all error messages. The redaction applies to the *value*, and
the resolved config records only which source supplied it (`env:SCANR_LAB_PASSWORD`).

## Recorded fidelity

`fidelity` is not something the user invents: it is the output of
`scanr transport test <name>`, which prints the exact line to paste. Declaring it turns
off the per-scan "not measured" warning and, for `open_only`, replaces it with a
specific statement of what non-open results will mean.

Keeping it in config rather than a cache file was deliberate. It is a property of a
proxy that rarely changes, it belongs in version control alongside the transport it
describes, and it appears in the scan record with its provenance — which a hidden cache
could not provide.

## Validation

`scanr config validate` checks: unknown keys (hard error, with the nearest known key
suggested); unknown `version`; unknown `fidelity` values; references to undefined profiles/transports/target
sets/port sets; malformed CIDRs, ranges, and durations; `rate` exceeding the ephemeral
budget (warning); inline passwords; `password_file` permissions; empty target or port
sets; hostnames present with `dns = "disabled"`.

Errors are reported with file, line, and a caret span from `toml`'s `Error::span()`.

## Generated reference

`scanr config init` writes a fully annotated `scanr.toml` — every field with its
default, valid range, explanation, whether CLI can override it, and whether it is
transport-specific. The annotations are generated from the same field metadata table
that drives validation and the override allowlist, so they cannot drift from the code.

## Migration

`version` is checked before deserialization. A future `version = 2` will be read by a
migration shim that rewrites into the current types; unknown *major* versions refuse to
load rather than guessing.
