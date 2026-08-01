# Security considerations

## Authorization

`scanr` connects to hosts you point it at. Port scanning without permission is unlawful in
many jurisdictions and against the terms of most networks. Scan only what you are
authorized to scan.

Nothing in this tool tries to be stealthy. There is no evasion, no timing obfuscation, no
source spoofing, and probe order randomization exists to spread load rather than to hide.
A `connect()` scan completes full TCP handshakes and is trivially visible in logs on the
destination.

## Trust boundaries

```
   you ──▶ scanr ──▶ [proxy] ──▶ destination
```

* **The proxy sees everything**: every destination address and port you ask for, in
  cleartext, plus your credentials if you use RFC 1929 authentication. A proxy you do not
  control is an observer of your entire scan.
* **The destination sees the proxy**, not you — which is usually the point. With the
  direct transport it sees your source address.
* **A hostile proxy can lie.** Every non-open verdict through a proxy is that proxy's
  assertion. It can report ports closed that are open, or open that are closed. `scanr`
  records `source: proxy_reply` on exactly those results so the distinction is visible in
  the record, but it cannot verify them.

## SOCKS5 authentication does not encrypt

RFC 1929 username/password authenticates you *to* the proxy. It provides no
confidentiality and no integrity. The credentials and the whole session cross the network
in cleartext. If the path to your proxy is untrusted, tunnel it — `ssh -D` gives you a
proxy whose transport is encrypted, at the cost of `open_only` result fidelity.

## Every hop in a chain sees the credentials of every hop after it

This is the property most likely to surprise, and it follows directly from how chaining
works. A chain reuses one socket: `scanr` completes the SOCKS5 handshake with hop 1, asks
it for a tunnel to hop 2, then performs hop 2's handshake **inside that tunnel**, and so on.

The consequence, for `hops = ["a", "b", "c"]`:

| what | who can read it |
|---|---|
| `a`'s credentials | the network path to `a`, and `a` |
| `b`'s credentials | all of the above, plus `b` |
| `c`'s credentials | all of the above, plus `c` |
| the destination and every probe result | every hop |

RFC 1929 sends the username and password with no confidentiality (above), and a tunnel
does not change that: hop 1 terminates its own encryption, so it reads the bytes you send
onward in cleartext. **Chaining through a hop is trusting it with every credential
downstream of it**, not just its own. Encrypting the link to hop 1 — `ssh -D`, say —
protects those bytes from an observer *on that link*, never from hop 1 itself.

Practical consequences:

- **Do not reuse one password across hops.** Give each hop its own, so a hop that logs or
  leaks what passes through it compromises only the hops after it.
- **Order matters.** The least trusted hop belongs last, where it sees the fewest secrets.
- **A pool is not a chain.** Members are probed *across*, never *through*, so a pool
  member sees only its own credentials and its own share of the destinations.

None of this is specific to `scanr` — it is how nested SOCKS5 works — but the tool makes
chains easy enough to build that the property is worth stating plainly.

## Credentials

**Inline passwords in configuration are rejected**, not warned about:

```
error: transport `lab` sets an inline `password`
help: scanr never reads inline passwords, because project config is
      normally committed to version control. Use one of:
        password_env  = "SCANR_LAB_PASSWORD"
        password_file = "~/.config/scanr/lab.password"
```

A warning is not protection when the expected workflow is to commit `./scanr.toml`.

`password_file` must be mode `0600` or narrower; loading fails otherwise.

Credentials are kept out of every output path:

- The scan record stores `"password": "[redacted]"` and the *source*
  (`env:SCANR_LAB_PASSWORD`), never the value.
- `plan` and `config show` redact.
- The in-memory type has a `Debug` implementation that prints `Secret([redacted])`, so a
  stray `{:?}` cannot leak one.
- The caret renderer redacts the value on a credential line, so an error *pointing at* a
  password does not print it. This was a real leak, found by an end-to-end test rather
  than by review: rejecting `password = "hunter2"` printed the password while doing so.
- `scanr output verify` scans a record for credential-shaped keys with real values, so a
  leak is caught by the tool rather than by a human reading the file.

Fuzzing covers the redaction path. Stating the property correctly took two attempts, both
defeated by the fuzzer — see `fuzz/fuzz_targets/config.rs`.

## DNS leakage

Resolving a hostname locally tells your resolver — and anyone observing it — what you are
about to scan, which defeats much of the point of scanning through a proxy.

| mode | who resolves | leaks locally | records the address probed |
|---|---|---|---|
| `transport` | the proxy | no | **no** |
| `local` | this host | **yes** | yes |
| `disabled` | nobody; hostnames rejected | no | n/a |
| `auto` | transport if supported, else local | depends | depends |

`auto` is the default. For a SOCKS5 transport it resolves remotely, so the default does not
leak. The tradeoff is that the address actually probed cannot be recorded: the SOCKS5
reply's `BND.ADDR` is the proxy's own bound address — measured as literally `0.0.0.0` from
`ssh -D` — not the destination's.

Because `auto` follows the transport, the same configuration can resolve differently when
you switch transports. `plan` prints the effective mode and warns when this applies.

## Untrusted input

`scanr` parses bytes from a proxy it does not control, including a peer-supplied length
field in the `ATYP_DOMAIN` bound address of a CONNECT reply. Five fuzz targets cover it:

| target | covers |
|---|---|
| `socks5_handshake` | greeting, method selection, RFC 1929 auth — the proxy chooses the method and supplies the status byte we act on |
| `socks5_reply` | the CONNECT reply parser, including the peer-supplied address length |
| `config` | loading, validation, and the caret renderer that slices source by byte offset |
| `specs` | target, port and duration parsing |
| `record` | reading a truncated or corrupted scan record |

See `fuzz/fuzz_targets/`. Seeds are committed and replayed in CI as a regression check.

Fuzzing found and fixed one real defect: an address-count overflow that panicked in debug
builds and silently wrapped in release, so `::/0` reported covering one address.

`unsafe_code` is denied crate-wide, so each of the five `unsafe` blocks is an explicit
`#[allow(unsafe_code)]` carrying a safety comment. All five are thin libc calls:

| where | call | why |
|---|---|---|
| `plan::permute` | `getrandom` | seed entropy (Linux) |
| `plan::permute` | `getentropy` | seed entropy (Apple) |
| `run` | `gethostname` | the scanning host, recorded in the record |
| `diag` | `getrlimit` | the file-descriptor budget warning |
| `cli` | `signal` | SIGINT/SIGTERM handling, and ignoring SIGPIPE/SIGXFSZ |

There is no `unsafe` anywhere else in the shipped crate — no raw-pointer data structures,
no transmutes, no manual synchronization. Adding a sixth block fails the build until
someone writes the comment justifying it. (The test harness has two more, both
`setrlimit` in a `pre_exec` closure, used to drive writer-failure paths. They do not ship.)

## What lands on disk

Every run writes a JSONL record to `output_dir` unconditionally. It contains every
destination probed and the outcome, which is a sensitive artifact: it is a map of what you
scanned and what answered.

- No credentials, by the guarantees above.
- The full resolved configuration, so the file explains itself.
- The scanning host's name and PID, plus the commit the binary was built from.

The record is created **mode 0600**, readable only by the user who ran the scan, and the
`.partial` file it is written through carries the same mode from the moment it exists.
Refusing a `password_file` that group or others can read while writing a world-readable
map of the target network would have been a contradiction. The containing `output_dir` is
created with the process umask, so tighten that directory yourself if its *name* is
sensitive — the record contents are not exposed by it.

Nothing is transmitted anywhere. There is no telemetry, no update check, and no network
activity beyond the probes you asked for and any DNS resolution the chosen mode implies.

## Privileges

None required, by design. `scanr` performs ordinary `connect()` calls. It does not need
`CAP_NET_RAW`, does not open raw sockets, and should not be run as root.
