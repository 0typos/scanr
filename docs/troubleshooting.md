# Troubleshooting

Keyed to what `scanr` reports; remediation in each diagnostic is derived from the host.

## Most results are `error`

```
completed in 2.31s — 0 open, 0 closed, 0 filtered, 64 error (64 of 64 probed)
  note: 64 of 64 probes returned `error`, so these results describe the
        scanner's environment more than the target
```

Cause: the environment, not the targets. Find which from the reasons:

```console
$ scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="error") | .reason' | sort | uniq -c
```

## `out of file descriptors` (`fd_pressure`)

```
warning: out of file descriptors
  out of file descriptors at concurrency 512.
  The soft RLIMIT_NOFILE is 1024. Either:
    - lower --concurrency below that limit, or
    - raise it:  ulimit -n 4096
```

Cause: one descriptor per in-flight probe; bites only when probes accumulate. Fix:
`ulimit -n`, or lower `--concurrency`. `scanr plan` warns first (`fd_budget`).

## `local ephemeral ports exhausted` (`ephemeral_pressure`)

```
warning: local ephemeral ports exhausted
  the local ephemeral port range (28232 ports) is exhausted.
  Every probe through a proxy consumes one source port, and Linux holds
  TIME_WAIT for 60s. Options, cheapest first:
   - lower --rate or --concurrency
   - widen the range:  sysctl -w net.ipv4.ip_local_port_range="10000 65535"
   - allow reuse for non-loopback too:  sysctl -w net.ipv4.tcp_tw_reuse=1
      (currently 2, which exempts loopback only)
```

Cause: one proxy per scan, so only the source port varies; 28,232 ports over a 60 s
`TIME_WAIT` caps sustained throughput near 470/s. Sockets close with `SO_LINGER{on,0}`
(RST, no `TIME_WAIT`, 7.5× throughput), so reaching this means the proxy is slow enough
for connections to pile up anyway. `tcp_tw_reuse = 2` exempts loopback only: a local
proxy escapes, a remote one does not. `plan` shows the regime and warns
(`ephemeral_budget`) when `rate` exceeds the ceiling for a remote proxy:

```
host            ephemeral 32768-60999 (28232 ports), tcp_tw_reuse=2 (loopback only), nofile=1048576
```

## `the proxy stopped accepting connections` (`proxy_saturation`)

```
warning: the proxy stopped accepting connections
  the proxy is refusing or timing out new connections, which means concurrency 256
  is more than it will accept.
  Results already recorded are still valid, but anything failing this way is
  recorded as `error` rather than as a port verdict. Options:
   - lower --concurrency (try halving it), or
   - use --profile proxy-careful, or
   - lower --rate if the proxy limits connection rate rather than count
```

Cause: the proxy's connection cap. Fix: raise it on the proxy rather than lower
concurrency — see [transports](transports.md#how-much-concurrency-will-it-take); measure
with `scanr transport test <name> --calibrate`. Reported once per scan.

## Everything is `filtered`

Cause: targets do not answer, or nothing reaches them. Probe a known-open port:

```console
$ scanr run --transport lab --targets <a-host-you-know-answers> --ports 22 --all
```

`filtered` there means the path.

## `closed` and `filtered` look wrong through a proxy

Cause: the proxy may not distinguish them. Run `scanr transport test <name>`; under
`open_only` non-open results are recorded as `error`, not guessed.

## `dns is disabled but N hostname target(s) were given`

Cause: the effective DNS mode rejects hostnames. Fix: supply addresses, or:

| flag | behaviour |
|---|---|
| `--dns local` | resolve here; multi-address names become several targets |
| `--dns transport` | hand hostnames to the proxy unresolved |

## Results have no `resolved_address`

Cause: transport-side DNS; the SOCKS5 reply's `BND.ADDR` is the proxy's bound address
(`0.0.0.0` from `ssh -D`), so the probed address is unknowable. Fix: `--dns local`, at
the cost of leaking queries and possibly resolving differently.

## The scan record ends in `.partial`

Cause: the process died before the terminal event. Results in it remain valid:

```console
$ scanr output verify scanr-results/scan-*.partial
  problem: no terminal event — the scan did not finish writing (process died?)
  problem: file still has the .partial suffix, meaning the process never finalized it
```

An interrupted but finalized scan is renamed normally with `scan_interrupted` in its
terminal event.

## Exit code 3

Cause: the output writer failed — full disk, permissions, file-size limit. The record
stays `.partial`; check the terminal event's `error` field if one was written.

## A scan is slower than expected

`plan` projects which limit binds:

```
rate            400/s                                   builtin.proxy
projection      ~10m39s at 400/s if every probe answers
                ~1h25m25s if every probe times out (5s x 2 attempts / 512 in flight)
```

| cause | note |
|---|---|
| `rate` set | likely it |
| silent hosts | a `/24` of non-answering hosts costs `connect_timeout` per probe ÷ concurrency |
| too much concurrency | throughput peaked near 512 threads, declined at 2048 |

## Localhost shows open ports in 32768-60999

Expected: the scanner draws its own source ports from the ephemeral range, so a port can
be occupied by the scan itself when probed (nmap reports the same). Only affects the host
the scan runs from; audit listeners with `ss -tlnp` instead. Check the range:

```console
cat /proc/sys/net/ipv4/ip_local_port_range
```

## 127.0.0.0/8 shows the same port open on every address

All of `127.0.0.0/8` routes to loopback, so a service on `0.0.0.0` answers on all
16,777,216 addresses: `127.16.0.0/16` port 22 on a host running sshd is 65,536 genuine
open results. Useful for load-testing a scanner, misleading otherwise.

## Every port on every host looks open

Cause: something in the path completes handshakes — transparent proxy, captive portal,
middlebox. Verify with a port nothing should listen on:

```console
$ scanr run --targets <host> --ports 1 --all
```

Port 1 `open` means the results cannot be trusted.
