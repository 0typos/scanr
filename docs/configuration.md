# Configuration

`scanr config init` writes an annotated `scanr.toml`: every field, default, range, CLI
override. That file is the field reference.

## Discovery

| layer | path |
|---|---|
| user | `~/.config/scanr/config.toml` or `$XDG_CONFIG_HOME/scanr/config.toml` |
| project | `./scanr.toml`, searched upward |

Both optional; `--config PATH` replaces both. Credentials and transports go in the user
file, scans in the committed project file.

```console
$ scanr config path
user      /home/you/.config/scanr/config.toml                 not present
project   /srv/assessments/acme/scanr.toml                    found
```

## Precedence

```
compiled default
  → built-in profile
  → user config
  → project config
  → selected profile
  → named scan
  → environment (credentials only)
  → CLI override
```

Per-key merge: overriding one field of `[profiles.proxy]` leaves the rest. Arrays replace
wholesale. `scanr plan` prints each value with its source layer
([example](getting-started.md#3-look-before-you-scan)).

## Service labels

From `/etc/services` where present, else a builtin table of 59 well-known ports. A guess
from the port number, not a fingerprint: 4444 is `krb524` to every layer.

```toml
[defaults]
services_file = "~/.config/scanr/services"   # yours wins, for the ports it names
use_etc_services = false                     # drop the host layer
```

```
internal-api   8080/tcp
build-cache    9099/tcp
metrics        9100/tcp   # aliases are fine
```

- `services_file`: `/etc/services` format (`name port/proto`, `#` comments, extra columns ignored; `nmap-services` works). Unreadable: scan stops. Bad lines: counted, warned.
- `use_etc_services = false`: labels from config and binary only, for diffing across machines (one host's `/etc/services` says `postgres` for 5432, the builtin `postgresql`).
- The record separates declined from absent (`service_labels.use_etc_services`) and names the files used: [output-schema.md](output-schema.md).

## Profiles

Seven built-ins. Flat and complete, no inheritance. `scanr config show` prints them.

| profile | concurrency | rate | connect | retries | for |
|---|---|---|---|---|---|
| `direct` | 512 | unlimited | 2s | 1 | routed networks, no proxy |
| `direct-fast` | 2048 | unlimited | 300ms | 1 | LAN, round trip under ~100ms |
| `proxy` | 512 | 400/s | 5s | 1 | self-hosted SOCKS5 (dante, microsocks), good link |
| `proxy-careful` | 64 | 50/s | 8s | 1 | rotating pools, or unknown limits |
| `ssh-fast` | 64 | unlimited | 2s | 0 | `ssh -D` to a nearby server (LAN, same DC) |
| `ssh` | 96 | unlimited | 6s | 1 | `ssh -D` over a typical internet link |
| `ssh-slow` | 128 | unlimited | 15s | 1 | `ssh -D` over a high-latency link |

- Default follows the transport: `proxy` for any proxy (socks5, http, chain, pool), else `direct`.
- `[profiles.proxy]` overrides only the fields set; a new name falls back to the transport-appropriate built-in.
- See [tuning.md](tuning.md) before changing these.
- Also profile fields: `banner_bytes` (1024), `banner_timeout` (500ms), `tls_timeout` (1s) — ceilings for the banner read and the TLS probe. `[defaults]` and a scan may set `tls` (false) and `tls_versions` (false, needs `tls`).

## Transports

```toml
[transports.lab]
type = "socks5"                       # or "http", "direct"
address = "127.0.0.1:1080"
username = "scanner"                  # optional, RFC 1929
password_env = "SCANR_LAB_PASSWORD"   # or password_file
dns = "auto"
fidelity = "full"                     # from `scanr transport test lab`
```

`direct` always exists undefined. `fidelity`: [transports.md](transports.md).

## Target sets

```toml
[targets.lab]
include = [
  "10.20.30.0/24",              # CIDR; network and broadcast included; host bits masked
  "10.20.31.10-10.20.31.20",    # inclusive range
  "10.20.32.7",                 # literal
  "app.internal",               # hostname
  "2001:db8::/112",             # IPv6 CIDR
]
exclude = ["10.20.30.1", "10.20.30.254"]   # applied after expansion

[targets.from-inventory]
file = "hosts.txt"              # one per line; blank lines and `#` comments skipped
```

Overlaps de-duplicated. Refused without `--allow-large-range`: over 4,000,000 addresses,
or IPv6 prefixes shorter than `/112` (65,536 addresses).

## Port sets

```toml
[ports.web]
ports = ["80", "443", "8000-8999"]

[ports.common]
ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
```

List or comma-separated string; `all` is 1-65535; de-duplicated; the plan records the
sorted set.

## Scans

```toml
[scans.internal-web]
description = "Internal web services through the lab proxy"
profile = "proxy"
transport = "lab"
targets = ["lab"]          # names from [targets.*], or literal specs
ports = ["web"]            # names from [ports.*], or literal specs
connect_timeout = "8s"     # any profile field, inline for this scan only
tls = true                 # the TLS ClientHello probe for this scan; off by default
```

An unmatched name is a literal spec: `targets = ["10.0.0.0/24"]` needs no set.

## DNS

```toml
dns = "auto"   # auto | transport | local | disabled
```

| mode | who resolves | leaks locally | records the address probed |
|---|---|---|---|
| `transport` | the proxy | no | no |
| `local` | this host | yes | yes |
| `disabled` | nobody; hostnames rejected | no | n/a |
| `auto` | transport if supported, else local | depends | depends |

- `transport`: SOCKS5 `BND.ADDR` is the proxy's bound address (`0.0.0.0` from `ssh -D`), so `resolved_address` is `null`.
- `local`: the resolver learns what is scanned; split-horizon DNS may resolve differently from the proxy.
- `auto` follows the transport, so one config differs per transport: a multi-address hostname expands direct, not proxied. `plan` shows the mode and warns.

## Validation

```console
$ scanr config validate
ok — 1 file(s), 2 scan(s), 3 transport(s)
```

```
error: unknown fidelity `ful` for transport `lab`
 --> ./scanr.toml:12:1
  |
12 | fidelity = "ful"
  | ^^^^^^^^
help: expected one of: full, open_only
      run `scanr transport test lab` to measure it
```

All problems at once, with line and nearest match. Unknown keys are errors.

## CLI overrides

An allowlist; timing knobs stay in config. Full list: [cli.md](cli.md#flags).

```
--profile  --transport  --targets  --ports  --exclude
--concurrency  --rate  --connect-timeout  --retries
--dns  --output-dir  --seed  --open-only/--all  --allow-large-range
```

## Versioning

`version = 1` is required; an unknown major version refuses to load.
