# Compatibility corpus

One record per product workflow, the exact output every reader must produce for it
(`expected/`), and the `config init` template of every release (`configs/`).
`tests/compat.rs` holds the current binary to all of it; `docs/stability.md` is the
promise it checks. Regenerate with the command in `tests/compat.rs` and review the diff.

| scenario | proves |
|---|---|
| `direct-mixed` | a direct scan records open, closed and filtered (spans on, gzip); verify passes and remainder reports it complete |
| `direct-rows` | the same scan as one row per probe, plain JSONL (`--no-spans --no-compress`); readers give the same answers |
| `socks5-full` | through a faithful SOCKS5 proxy a refused port is `closed` with `source: proxy_reply` |
| `socks5-open-only` | through a proxy that collapses failures, non-open results are `error`, never a fabricated `closed` |
| `http-proxy` | through an HTTP CONNECT proxy the transport is `open_only` by construction and non-open results carry the status line |
| `chain-http-socks5` | a chain of http → socks5 records both hops with their protocols and keeps the SOCKS5 exit's `full` fidelity |
| `pool` | a pool assigns each endpoint to a member deterministically and records `via` on every result |
| `banner-tls` | a greeting service is recorded verbatim and never probed; a silent TLS service yields certificate, cipher and ALPN under `--tls` |
| `interrupted` | Ctrl-C leaves a finalised record whose counts account for every planned probe (completed + abandoned + not_started) |
| `resumed` | `output remainder | run --pairs -` probes exactly what was outstanding and links the new record to the old via `resumed_from` |
| `v1-0.2.2` | a schema_version 1 record written by the 0.2.2 release reads back through every reader of the current binary |

Readers pinned per scenario: `verify.txt`, `summarize.txt`, `summarize.json`, `results.txt`, `results.json`, `results-open.list`, `results-open.nmap`, `remainder.txt`
