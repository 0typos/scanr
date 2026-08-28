# Security considerations

## Authorization

Port scanning without permission is unlawful in many jurisdictions and against most
networks' terms. Scan only what you are authorized to scan. Nothing is stealthy. There is
no evasion, timing obfuscation or source spoofing; randomized order only spreads load. A
`connect()` scan completes full handshakes and is visible in destination logs.

## Trust boundaries

```
   you ──▶ scanr ──▶ [proxy] ──▶ destination
```

| party | sees |
|---|---|
| proxy | every destination and port in cleartext, plus RFC 1929 credentials: the entire scan |
| destination | the proxy's address; with the direct transport, yours |

A hostile proxy can lie. Every non-open verdict through it is the proxy's assertion,
recorded with `source: proxy_reply` and unverifiable.

## Proxy authentication does not encrypt

RFC 1929 (`socks5`) and Basic (`http`, base64) authenticate you *to* the proxy;
credentials and session cross the wire in cleartext, see
[transports](transports.md#authentication). On an untrusted path, tunnel it with
`ssh -D` at the cost of `open_only` fidelity.

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

- Use one password per hop, so a leaking hop compromises only the hops after it.
- Put the least trusted hop last, where it sees the fewest secrets.
- A pool is not a chain. Members are probed *across*, never *through*; each sees only its
  own credentials and share of destinations.

## Credentials

scanr rejects inline passwords, because project config is normally committed:

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
transport, so it does not leak. The probed address then goes unrecorded, since the
reply's `BND.ADDR` is the proxy's own; `ssh -D` returns `0.0.0.0`. Because `auto` follows
the transport, one configuration can resolve differently per transport. `plan` prints
the effective mode and warns.

## The one active probe

Everything else scanr does is connect and listen. `--tls` (or `tls = true`) sends one
thing: a fixed ClientHello offering TLS 1.3 and 1.2, to open ports that volunteered no
banner, on the connection the scan already made. It addresses the service rather than
observing it. That is why it is off by default and why the record states
`tls.sent_bytes`, `0` when it never ran.

The 218 bytes sent. An SNI extension is added when the target was given as a name,
whether scanr resolved it or the proxy will:

```
16030100d5010000d103037363616e7220746c732070726f62653a206e6f7420
72616e646f6d202076312000002a1301c02cc02bc030c02fcca9cca8c024c023
c028c027c00ac009c014c013009d009c003d003c0035002f0100007e000a0008
0006001d00170018000b00020100000d001a0018040305030603080408050806
0807040105010601020302010010000e000c02683208687474702f312e310017
0000ff01000100002b00050403040303003300260024001d00207759e0be15bc
4d8af57fb9dcf4a14d73dcc56bf9a1ebc75dce3fbe0297cfd736
```

The client random is a fixed string. The cipher suites are `TLS_AES_128_GCM_SHA256`,
the one every 1.3 server must implement, and twenty common 1.2 suites. ALPN offers `h2`
and `http/1.1`. `supported_versions` names 1.3 then 1.2. `key_share` carries one x25519
point, computed from the private key published as `PROBE_X25519_PRIVATE` in
`src/tls.rs`. A test holds this document to the bytes the code sends. `scan_config.tls`
lists the offered cipher suites, ALPN, groups and signature schemes by name, and under
`--tls-versions` its `version_hellos` names the suites each survey hello offers, so a
record states every offer without pointing here.

A server that picks 1.2 or older sends its first flight in the clear: ServerHello,
Certificate, ServerKeyExchange, ServerHelloDone, or an Alert. scanr reads it. A server
that picks 1.3 encrypts everything after its ServerHello, so scanr finishes the key
exchange and decrypts the flight up to Finished. The key exchange is X25519 with that
published key, the RFC 8446 schedule and AES-128-GCM, all in `src/crypto.rs` with an RFC
or NIST vector for each. Nothing is sent after the hello. The server's Finished is not
answered, no application data ever exists, and the socket is reset. A published private
key means anyone holding a capture can read the same flight, which is the point; nothing
in it was ever secret. A server that wants a different key-share group answers
HelloRetryRequest, which is recorded as such and not pursued. Neither the certificate
nor the signature is verified, in 1.3 or 1.2.

### The version survey

A server answers a hello with the highest version it shares, never with the lowest it
still accepts, so one hello cannot say whether SSLv3 is still spoken. `--tls-versions`
(`tls_versions = true`, needs `tls`) asks. After the main hello, each of SSLv2, SSLv3,
TLS 1.0 and 1.1, plus 1.2 when the server took 1.3, is offered on its own connection
with a hello of its era, and the answer is recorded per version. That is up to five more
connections per silent open port, each counted in `tls.versions.connections`. The
record's `legacy_only` and `advice` say when no current client can reach the server and
what can. SNI is added to the 1.0, 1.1 and 1.2 hellos when the target was given as a
name; SSLv3 and SSLv2 get none, as their servers expect. The hellos, byte for byte:

SSLv2 CLIENT-HELLO, 48 bytes, every cipher kind, a fixed challenge:

```
802e0100020015000000100100800200800300800400800500800600400700c0
7363616e722073736c322070726f6265
```

SSLv3, 80 bytes, sixteen suites of the era, no extensions block at all:

```
160300004b0100004703007363616e7220746c732070726f62653a206e6f7420
72616e646f6d2020763120000020c014c013c00ac009003900330035002f0016
000a0005000400090003000600080100
```

TLS 1.0 and 1.1, 80 bytes each, the SSLv3 hello with the version fields changed:

```
160301004b0100004703017363616e7220746c732070726f62653a206e6f7420
72616e646f6d2020763120000020c014c013c00ac009003900330035002f0016
000a0005000400090003000600080100
```

```
160302004b0100004703027363616e7220746c732070726f62653a206e6f7420
72616e646f6d2020763120000020c014c013c00ac009003900330035002f0016
000a0005000400090003000600080100
```

TLS 1.2, 165 bytes, the main hello without its 1.3 suite, `supported_versions` and key
share. Sent only when the main hello was answered with 1.3:

```
16030100a00100009c03037363616e7220746c732070726f62653a206e6f7420
72616e646f6d2020763120000028c02cc02bc030c02fcca9cca8c024c023c028
c027c00ac009c014c013009d009c003d003c0035002f0100004b000a00080006
001d00170018000b00020100000d001a00180403050306030804080508060807
040105010601020302010010000e000c02683208687474702f312e3100170000
ff01000100
```

The same bounded flight reader as the main hello reads each answer, except the SSLv2
answer, which has its own reader: a two- or three-byte record header, a SERVER-HELLO
whose certificate is taken in the clear and stands in for the leaf when nothing newer
answered, cipher kinds named, lengths bounded at 32 KiB.

The survey opens each version's connection in turn and waits out to the same ceiling the
main probe uses, which scales off the measured connect. A concurrent server answers every
one. A strictly single-connection server that is slow to service a fresh reconnect can
time out a version and under-report it as `accepted: null`, `detail: "no reply"`. This
shows against `openssl s_server`, which is single-threaded; the differential test still
verifies its answers without the survey. Real servers and the concurrent in-process
fixture survey completely.

What comes back is peer-chosen and treated as such. Record and message lengths are
bounded, 64 KiB per flight and 8 KiB for the embedded leaf. The read is deadline-driven.
The ALPN string is filtered to printable ASCII. The leaf certificate is stored as base64
DER for other tools to verify.

scanr reads the leaf and the certificates after it but verifies nothing. `src/x509.rs`
lifts subject, issuer, alternative names, validity window, serial, signature and key
algorithms with a DER walker whose nesting is fixed by the code rather than the input.
Every length is checked against the bytes present, strings are reduced to printable
ASCII and capped at 253 bytes, and at most 64 alternative names are kept, all counted.
`self_signed` means issuer equals subject byte for byte; no signature is checked.
Fuzzed: `x509_leaf`.

## Untrusted input

scanr parses bytes from an uncontrolled proxy, including a peer-supplied length in the
`ATYP_DOMAIN` bound address of a CONNECT reply, the length of an HTTP CONNECT response,
and every length in a TLS server flight and its certificate. Eight fuzz targets under
`fuzz/fuzz_targets/`, seeds committed and replayed in CI:

| target | covers |
|---|---|
| `socks5_handshake` | greeting, method selection, RFC 1929 auth; the proxy picks the method and status byte |
| `socks5_reply` | CONNECT reply parser, including the address length |
| `http_connect_reply` | HTTP CONNECT response parser: status line, header block bound, printable filtering |
| `tls_reply` | TLS server flight, 1.2 in the clear and 1.3 through the key exchange: record, handshake and certificate lengths; ALPN filtering; leaf bound; a record that does not decrypt |
| `x509_leaf` | the leaf certificate: DER tags and lengths, names, times, alternative names; strings printable; the same answer twice |
| `config` | loading, validation, the caret renderer's byte-offset slicing |
| `specs` | target, port and duration parsing |
| `record` | truncated or corrupted records |

Fuzzing found one real defect: an address-count overflow that panicked in debug and
wrapped in release, so `::/0` reported one address.

`unsafe_code` is denied crate-wide; each block is an explicit `#[allow(unsafe_code)]`
with a safety comment. All five are thin libc calls:

| where | call | why |
|---|---|---|
| `plan::permute` | `getrandom` | seed entropy (Linux) |
| `plan::permute` | `getentropy` | seed entropy (Apple) |
| `run` | `gethostname` | scanning host, recorded |
| `diag` | `getrlimit` | file-descriptor budget warning |
| `cli` | `signal` | SIGINT/SIGTERM; ignoring SIGPIPE/SIGXFSZ |

No other `unsafe` ships; a sixth block fails the build. The test harness has two more,
both `setrlimit` in a `pre_exec` closure.

## What lands on disk

Every run writes a record to `output_dir`, a map of what was scanned and what answered.
It holds the full resolved configuration and the host's name, PID and build commit, and
no credentials. Record and `.partial` are created mode `0600`. `output_dir` follows the
umask, so tighten it if the directory *name* is sensitive. There is no telemetry, no
update check, and no network activity beyond the probes and the DNS the chosen mode
implies.

## Privileges

None. Ordinary `connect()` calls, no `CAP_NET_RAW`, no raw sockets. Do not run as root.
