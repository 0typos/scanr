# Security considerations

## Authorization

Port scanning without permission is unlawful in many jurisdictions and against most
networks' terms. Scan only what you are authorized to scan. Nothing is stealthy: no
evasion, timing obfuscation or source spoofing; randomized order spreads load. A
`connect()` scan completes full handshakes and is visible in destination logs.

## Trust boundaries

```
   you ──▶ scanr ──▶ [proxy] ──▶ destination
```

| party | sees |
|---|---|
| proxy | every destination and port in cleartext, plus RFC 1929 credentials: the entire scan |
| destination | the proxy's address; with the direct transport, yours |

A hostile proxy can lie: every non-open verdict through it is its assertion, recorded
with `source: proxy_reply` but unverifiable.

## Proxy authentication does not encrypt

RFC 1929 (`socks5`) and Basic (`http`, base64) authenticate you *to* the proxy;
credentials and session cross the wire in cleartext
([transports](transports.md#authentication)). Untrusted path: tunnel it with `ssh -D`,
at the cost of `open_only` fidelity.

## Every hop in a chain sees the credentials of every hop after it

A chain reuses one socket: hop 1's handshake, a tunnel to hop 2, hop 2's handshake inside
it, and so on. For `hops = ["a", "b", "c"]`:

| what | who can read it |
|---|---|
| `a`'s credentials | the network path to `a`, and `a` |
| `b`'s credentials | all of the above, plus `b` |
| `c`'s credentials | all of the above, plus `c` |
| the destination and every probe result | every hop |

Hop 1 terminates its own encryption and reads the onward bytes in cleartext; `ssh -D` to
it protects against an observer *on that link*, never hop 1. This is nested CONNECT
tunnelling, not `scanr`, and holds for `socks5` and `http` hops alike.

- One password per hop: a leaking hop compromises only the hops after it.
- Least trusted hop last, where it sees the fewest secrets.
- A pool is not a chain: members are probed *across*, never *through*; each sees only its
  own credentials and share of destinations.

## Credentials

Inline passwords are rejected, because project config is normally committed:

```
error: transport `lab` sets an inline `password`
help: scanr never reads inline passwords, because project config is
      normally committed to version control. Use one of:
        password_env  = "SCANR_LAB_PASSWORD"
        password_file = "~/.config/scanr/lab.password"
```

`password_file` must be mode `0600` or narrower.

| path | behaviour |
|---|---|
| scan record | `"password": "[redacted]"` plus the source (`env:SCANR_LAB_PASSWORD`) |
| `plan`, `config show` | redact |
| in-memory type | `Debug` prints `Secret([redacted])` |
| caret renderer | redacts a credential line, so an error *pointing at* a password does not print it |
| `scanr output verify` | fails a record whose credential-shaped keys hold real values |

Fuzzed: `fuzz/fuzz_targets/config.rs`.

## DNS leakage

Local resolution tells your resolver what is about to be scanned. Modes:
[configuration](configuration.md#dns). `auto` (default) resolves through a SOCKS5
transport, so it does not leak; the probed address then goes unrecorded, since the
reply's `BND.ADDR` is the proxy's own (literally `0.0.0.0` from `ssh -D`). `auto` follows
the transport, so one configuration can resolve differently per transport; `plan` prints
the effective mode and warns.

## The one active probe

Everything else scanr does is connect and listen. `--tls` (or `tls = true`) sends one
thing: a fixed TLS 1.2 ClientHello, to open ports that volunteered no banner, on the
connection the scan already made. It addresses the service rather than observing it,
which is why it is **off by default** and why the record states `tls.sent_bytes` — `0`
when it never ran.

What is sent, byte for byte (163 bytes; an SNI extension is added when the target was
given as a name, whether scanr resolved it or the proxy will):

```
160301009e0100009a03037363616e7220746c732070726f62653a206e6f7420
72616e646f6d2020763120000028c02cc02bc030c02fcca9cca8c024c023c028
c027c00ac009c014c013009d009c003d003c0035002f01000049000a00080006
001d00170018000b00020100000d001800160403050306030804080508060401
05010601020302010010000e000c02683208687474702f312e3100170000ff01
000100
```

Client random is a fixed string, cipher suites are twenty common TLS 1.2 suites, ALPN
offers `h2` and `http/1.1`, and there is no `supported_versions` extension, so nothing
newer than 1.2 is ever negotiated. The server's first flight is read — ServerHello,
Certificate, or an Alert — and the socket is reset. No key exchange, no verification,
no bytes after the flight. A test holds this document to the bytes the code sends.

What comes back is peer-chosen and treated as such: record and message lengths are
bounded (64 KiB flight, 8 KiB embedded leaf), the read is deadline-driven, the ALPN
string is filtered to printable ASCII, and the leaf certificate is stored as base64 DER
for other tools to verify.

scanr reads the leaf but verifies nothing. `src/x509.rs` lifts subject, issuer,
alternative names, validity window and key type with a DER walker whose nesting is
fixed by the code rather than the input, every length checked against the bytes
present, strings reduced to printable ASCII and capped at 253 bytes, at most 64
alternative names kept (all counted). `self_signed` means issuer equals subject byte for
byte — no signature is checked. Fuzzed: `x509_leaf`.

## Untrusted input

Bytes from an uncontrolled proxy are parsed, including a peer-supplied length in the
`ATYP_DOMAIN` bound address of a CONNECT reply and the length of an HTTP CONNECT
response, and every length in a TLS server flight and its certificate. Eight fuzz targets under
`fuzz/fuzz_targets/`, seeds committed and replayed in CI:

| target | covers |
|---|---|
| `socks5_handshake` | greeting, method selection, RFC 1929 auth; the proxy picks the method and status byte |
| `socks5_reply` | CONNECT reply parser, including the address length |
| `http_connect_reply` | HTTP CONNECT response parser: status line, header block bound, printable filtering |
| `tls_reply` | TLS server flight: record, handshake and certificate lengths; ALPN filtering; leaf bound |
| `x509_leaf` | the leaf certificate: DER tags and lengths, names, times, alternative names; strings printable; the same answer twice |
| `config` | loading, validation, the caret renderer's byte-offset slicing |
| `specs` | target, port and duration parsing |
| `record` | truncated or corrupted records |

One real defect found: an address-count overflow that panicked in debug and wrapped in
release, so `::/0` reported one address.

`unsafe_code` is denied crate-wide; each block is an explicit `#[allow(unsafe_code)]`
with a safety comment. All five are thin libc calls:

| where | call | why |
|---|---|---|
| `plan::permute` | `getrandom` | seed entropy (Linux) |
| `plan::permute` | `getentropy` | seed entropy (Apple) |
| `run` | `gethostname` | scanning host, recorded |
| `diag` | `getrlimit` | file-descriptor budget warning |
| `cli` | `signal` | SIGINT/SIGTERM; ignoring SIGPIPE/SIGXFSZ |

No other `unsafe` ships; a sixth block fails the build. The test harness has two more
(`setrlimit` in a `pre_exec` closure).

## What lands on disk

Every run writes a record to `output_dir`: a map of what was scanned and what answered.
It holds no credentials, the full resolved configuration, and the host's name, PID and
build commit. Record and `.partial` are created mode `0600`; `output_dir` follows the
umask, so tighten it if the directory *name* is sensitive. No telemetry, update check, or
network activity beyond the probes and the DNS the chosen mode implies.

## Privileges

None: ordinary `connect()` calls, no `CAP_NET_RAW`, no raw sockets. Do not run as root.
