# Troubleshooting

Keyed to what `scanr` actually reports. Every diagnostic below is emitted by the tool
with remediation derived from the machine it is running on.

## Most of my results are `error`

`scanr` says so explicitly rather than letting `completed` imply success:

```
completed in 2.31s — 0 open, 0 closed, 0 filtered, 64 error (64 of 64 probed)
  note: 64 of 64 probes returned `error`, so these results describe the
        scanner's environment more than the target
```

Look at the reason on a result to find out which case it is:

```console
$ jq -r 'select(.type=="probe_result" and .state=="error") | .reason' scan-*.jsonl | sort | uniq -c
```

## `out of file descriptors`

```
warning: out of file descriptors
  out of file descriptors at concurrency 512.
  The soft RLIMIT_NOFILE is 1024. Either:
    - lower --concurrency below that limit, or
    - raise it:  ulimit -n 4096
```

Each in-flight probe holds one descriptor. `scanr plan` warns about this *before* a scan
when concurrency exceeds the limit, so `plan` is worth running first.

Note that this only bites when probes actually accumulate — against destinations that
refuse instantly, descriptors are released as fast as they are taken.

## `local ephemeral ports exhausted`

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

With one proxy per scan, every probe connects to the *same* socket address, so only the
source port varies. The default range is 28,232 ports and Linux holds `TIME_WAIT` for a
hardcoded 60s, which caps sustained throughput near 470/s.

`scanr` closes probe sockets with `SO_LINGER{on,0}` so they send RST and skip `TIME_WAIT`
entirely, which lifts that ceiling substantially — measured as a 7.5× throughput
multiplier. If you are still hitting it, the proxy is likely slow enough that connections
pile up anyway.

`tcp_tw_reuse = 2` is the modern default and exempts **loopback only**. A local proxy
escapes this; a remote one does not. `scanr plan` reports which regime you are in:

```
host            ephemeral 32768-60999 (28232 ports), tcp_tw_reuse=2 (loopback only), nofile=1048576
```

## `the proxy stopped accepting connections`

```
warning: the proxy stopped accepting connections
  the proxy is refusing or timing out new connections, which means concurrency 256
  is more than it will accept.
   - lower --concurrency (try halving it), or
   - use --profile proxy-careful, or
   - lower --rate if the proxy limits connection rate rather than count
```

Usually a connection cap on the proxy. Raising it there is generally better than lowering
concurrency — see [transports](transports.md#how-much-concurrency-will-it-take). Measure
yours with `scanr transport test <name> --calibrate`.

This is reported at most once per scan; a saturated proxy would otherwise produce one
warning per failing probe.

## Everything is `filtered`

Either the targets genuinely do not answer, or nothing is reaching them at all. To tell
the difference, probe something you know is open:

```console
$ scanr run --transport lab --targets <a-host-you-know-answers> --ports 22 --all
```

If that is also `filtered`, the problem is the path, not the targets.

## `closed` and `filtered` look wrong through my proxy

They may be unavailable. Run `scanr transport test <name>`. If it reports `open_only`,
your proxy cannot distinguish them and `scanr` records non-open results as `error` rather
than guessing. That is the honest answer, not a bug.

## `dns is disabled but N hostname target(s) were given`

The effective DNS mode rejects hostnames. Either supply addresses, or choose a mode:

- `--dns local` resolves on this host; multi-address names become several targets
- `--dns transport` hands hostnames to the proxy unresolved

## Results have no `resolved_address`

Expected under transport-side DNS. The SOCKS5 reply's `BND.ADDR` is the proxy's bound
address, not the destination's — measured as literally `0.0.0.0` from `ssh -D` — so the
address actually probed is not knowable. Use `--dns local` if you need it recorded, at the
cost of leaking queries and possibly resolving differently than the far side.

## The scan record ends in `.jsonl.partial`

The process died without writing a terminal event. The results in it are still valid;
`scanr output verify` will tell you it was truncated:

```console
$ scanr output verify scanr-results/scan-*.jsonl.partial
  problem: no terminal event — the scan did not finish writing (process died?)
  problem: file still has the .partial suffix, meaning the process never finalized it
```

A file that was interrupted but finalized cleanly is renamed normally and says
`scan_interrupted` in its terminal event. `.partial` means specifically "the process
died".

## Exit code 3

The output writer failed — a full disk, a permissions problem, or a file-size limit. The
record stays `.partial`. Check the terminal event's `error` field if one was written.

## A scan is slower than expected

Check which limit is binding, which `plan` projects:

```
rate            400/s                                   builtin.proxy
projection      ~10m39s at 400/s
```

If `rate` is set, that is likely it. If unlimited, the constraint is timeouts against
unresponsive hosts: a `/24` where most hosts do not answer costs `connect_timeout` per
probe divided by concurrency.

Also worth knowing: concurrency is not monotonically better. Measured throughput peaked
near 512 threads and declined at 2048.

## Scanning localhost shows unexpected open ports in the 32768-60999 range

Expected, and not specific to `scanr`. That range is the local ephemeral port range, and
a scanner running on the same host draws its own outbound source ports from it. A port can
therefore be genuinely occupied *by the scan itself* at the moment it is probed, and both
`scanr` and nmap will correctly report it open.

Check the range in use:

```console
cat /proc/sys/net/ipv4/ip_local_port_range
```

If you are auditing what a machine listens on, prefer `ss -tlnp` over scanning its own
loopback. This only affects scanning the host you are scanning *from*; for a remote target
the source and destination ports are unrelated.

## Every port on every host looks open

Something in the path is answering on your behalf — a transparent proxy, a captive
portal, or a middlebox that completes handshakes. A connect scan cannot distinguish that
from a genuinely open port. Verify with a port nothing should be listening on:

```console
$ scanr run --targets <host> --ports 1 --all
```

If port 1 is `open`, do not trust the results.
