# Configuration

`scanr config init` writes a fully annotated `scanr.toml` with every field, its default,
its range, and whether the CLI can override it. That file is the reference; this is the
narrative.

## Discovery

Two optional files:

1. `~/.config/scanr/config.toml` — or `$XDG_CONFIG_HOME/scanr/config.toml`
2. `./scanr.toml` — searched upward from the working directory

`--config PATH` replaces both. `scanr config path` shows what was found:

```console
$ scanr config path
user      /home/you/.config/scanr/config.toml                 not present
project   /srv/assessments/acme/scanr.toml                    found
```

The intended split: **transports and credentials in the user file, scan definitions in the
project file**, because the project file is normally committed and the credentials must not
be.

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

Merging is **per-key**, not per-table: a project file overriding one field of
`[profiles.proxy]` leaves its other fields intact. Arrays replace wholesale — appending is
never what you want for a target list you are trying to control.

You never have to reason about this from the outside. `scanr plan` prints the effective
value of every field and which layer supplied it:

```console
$ scanr plan internal-web
scan            internal-web
profile         proxy                                   builtin
transport       lab (socks5)                            scan.internal-web
  address       127.0.0.1:1080
  fidelity      full                                    declared in config
dns             auto -> transport                       transport.lab
targets         255 (10.20.30.0/24)
ports           1002 (80,443,8000-8999)
probes          255,510
order           randomized, seed 9f2c00a1b4de7731       builtin
concurrency     512                                     profile.proxy
rate            400/s                                   builtin.proxy
connect_timeout 8s                                      cli
```

## Service labels

`scanr` labels each port with what usually listens there. By default that is
`/etc/services` where the host has one, falling back to a compiled-in table of 59
well-known ports.

To label your own ports, point at a file:

```toml
[defaults]
services_file = "~/.config/scanr/services"
```

It takes `/etc/services` format — `name port/proto`, `#` to end of line a comment, extra
columns ignored — so an `nmap-services` file works too:

```
internal-api   8080/tcp
build-cache    9099/tcp
metrics        9100/tcp   # aliases are fine
```

Your file wins over `/etc/services`, which wins over the builtin table, and only for the
ports it mentions. Three lines does not cost you the other 5,000.

A file that cannot be read stops the scan — if you named it, you meant it. Lines that
do not parse are counted and warned about, and the scan continues.

If you need labels that match on every machine — comparing a scan from a CI runner
against one from a laptop, say — drop the host layer:

```toml
[defaults]
use_etc_services = false
```

Labels then depend only on your config and the binary. You lose coverage, not control:
your own file and the builtin table both still apply. It matters more often than it
sounds: this machine's `/etc/services` calls 5432 `postgres` where the builtin says
`postgresql`, and that is enough to break a naive diff of two records.

The record distinguishes *declined* from *absent* — `service_labels.use_etc_services` —
because a container with no `/etc/services` and a config that turned it off otherwise
look identical.

This is still a guess from the port number, never a fingerprint: nothing connects to the
service or reads a banner. Port 4444 is `krb524` to every layer and is essentially never
Kerberos. Every record states which files produced its labels, so scans from two
machines can be compared — see [output-schema.md](output-schema.md).

## Profiles

Seven built-ins. **Flat and complete — no inheritance**, so what you read is what runs.
`scanr config show` prints them with their current values.

| profile | concurrency | rate | connect | retries | for |
|---|---|---|---|---|---|
| `direct` | 512 | unlimited | 2s | 1 | routed networks with no proxy in the path |
| `direct-fast` | 2048 | unlimited | 300ms | 1 | LAN, round trip known under ~100ms |
| `proxy` | 512 | 400/s | 5s | 1 | self-hosted SOCKS5 (dante, microsocks) on a good link |
| `proxy-careful` | 64 | 50/s | 8s | 1 | rotating pools, or limits you do not know |
| `ssh-fast` | 64 | unlimited | 2s | 0 | `ssh -D` to a nearby server (LAN, same DC) |
| `ssh` | 96 | unlimited | 6s | 1 | `ssh -D` over a typical internet link |
| `ssh-slow` | 128 | unlimited | 15s | 1 | `ssh -D` over a high-latency or long-haul link |

With nothing selecting a profile, the default **follows the transport**: `proxy` for
SOCKS5, `direct` otherwise. Otherwise a direct ad-hoc scan would inherit the proxy
profile's rate limit for no reason.

Defining `[profiles.proxy]` overrides only the fields you set; the rest of the built-in
stands. Defining a new name gives you a profile whose unset fields fall back to the
transport-appropriate built-in.

See [tuning](tuning.md) before changing these.

## Transports

```toml
[transports.lab]
type = "socks5"                       # or "direct"
address = "127.0.0.1:1080"
username = "scanner"                  # optional, RFC 1929
password_env = "SCANR_LAB_PASSWORD"   # or password_file
dns = "auto"
fidelity = "full"                     # from `scanr transport test lab`
```

`direct` always exists without being defined. See [transports](transports.md) for what
`fidelity` means and why it is worth recording.

## Target sets

```toml
[targets.lab]
include = [
  "10.20.30.0/24",              # CIDR; network and broadcast are included
  "10.20.31.10-10.20.31.20",    # inclusive range
  "10.20.32.7",                 # literal
  "app.internal",               # hostname
  "2001:db8::/112",             # IPv6 CIDR
]
exclude = ["10.20.30.1", "10.20.30.254"]

[targets.from-inventory]
file = "hosts.txt"              # one per line; blank lines and `#` comments skipped
```

`exclude` is applied after expansion, and overlapping includes are de-duplicated.

Two guards, both bypassable with `--allow-large-range`:

- expansion above 4,000,000 addresses is refused
- IPv6 prefixes shorter than `/112` (65,536 addresses) are refused

Host bits in a CIDR are masked rather than rejected: `10.0.0.5/24` means the whole `/24`,
matching near-universal usage.

## Port sets

```toml
[ports.web]
ports = ["80", "443", "8000-8999"]

[ports.common]
ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
```

Either a list or one comma-separated string. `all` means 1-65535. Duplicates are
de-duplicated and the resolved plan records the canonical sorted set.

## Scans

```toml
[scans.internal-web]
description = "Internal web services through the lab proxy"
profile = "proxy"
transport = "lab"
targets = ["lab"]          # names from [targets.*], or literal specs
ports = ["web"]            # names from [ports.*], or literal specs
connect_timeout = "8s"     # any profile field, inline for this scan only
```

A value that matches no defined set is parsed as a literal spec, so
`targets = ["10.0.0.0/24"]` works without defining a set first.

## DNS

```toml
dns = "auto"   # auto | transport | local | disabled
```

| mode | who resolves | leaks locally | records the address probed |
|---|---|---|---|
| `transport` | the proxy | no | **no** |
| `local` | this host | yes | yes |
| `disabled` | nobody; hostnames rejected | no | n/a |
| `auto` | transport if supported, else local | depends | depends |

The tradeoff is unavoidable. Under transport-side resolution the SOCKS5 reply's
`BND.ADDR` is the proxy's own bound address, not the destination's — measured as literally
`0.0.0.0` from `ssh -D` — so `resolved_address` is `null`. Local resolution records the
address but tells your resolver what you are scanning, and under split-horizon DNS may
resolve to different addresses than the proxy would, meaning you scan the wrong hosts.

Because `auto` follows the transport, **the same config can behave differently when you
change transports** — including expanding a multi-address hostname into several targets on
the direct path but not the proxied one. `plan` prints the effective mode and warns when
this applies.

## Validation

```console
$ scanr config validate
ok — 1 file(s), 2 scan(s), 3 transport(s)
```

Errors point at the line, with a nearest-match suggestion for a typo:

```
error: unknown fidelity `ful` for transport `lab`
 --> ./scanr.toml:12:1
  |
12 | fidelity = "ful"
  | ^^^^^^^^
help: expected one of: full, open_only
      run `scanr transport test lab` to measure it
```

All problems are reported at once, so one pass fixes the file. Unknown keys are hard
errors rather than being ignored.

## CLI overrides

Deliberately an allowlist. Timing knobs that belong in configuration are absent, which is
what keeps a run reproducible from a file rather than from shell history:

```
--profile  --transport  --targets  --ports  --exclude
--concurrency  --rate  --connect-timeout  --retries
--dns  --output-dir  --seed  --open-only/--all  --allow-large-range
```

`--seed` exists so a randomized scan can be replayed exactly.

## Versioning

`version = 1` is required. An unknown major version refuses to load rather than guessing.
