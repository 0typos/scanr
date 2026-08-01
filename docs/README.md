# scanr documentation

The [README](../README.md) covers what the tool is and why you would use it. For a first
session from install to a verified record, start with
**[getting-started.md](getting-started.md)**.

| | |
|---|---|
| [getting-started.md](getting-started.md) | Install, first scan, and checking the result |
| [cli.md](cli.md) | Every command and flag, stream behaviour, exit codes |
| [configuration.md](configuration.md) | File discovery, precedence, profiles, targets, ports, DNS, service labels |
| [transports.md](transports.md) | Direct and SOCKS5, and what your proxy can actually tell you |
| [output-schema.md](output-schema.md) | The scan record, its guarantees, and `jq` recipes |
| [tuning.md](tuning.md) | Where the real limits are, with measured numbers |
| [troubleshooting.md](troubleshooting.md) | Keyed to the diagnostics the tool emits |
| [security.md](security.md) | Trust boundaries, credentials, DNS leakage, authorization |

`cli.md` and `output-schema.md` are checked against the binary by tests, so neither can
drift from what the tool does.

Man pages are in [`../man/`](../man), one per command, generated from the CLI definition
and likewise test-checked. `cargo run --example gen_man` regenerates them.

## Working on scanr

| | |
|---|---|
| [design/decisions.md](design/decisions.md) | Why the tool is built the way it is: every significant decision with its alternatives, rationale, and the trigger that would justify revisiting it |
| [design/architecture.md](design/architecture.md) | Module boundaries, scheduler, writer, error model, dependency rationale |
| [../RELEASING.md](../RELEASING.md) | Cutting a release |

Read the decisions first. It records the assumptions that turned out to be **wrong** as
prominently as the ones that held — `ssh -D` does not collapse reply codes the way the
documentation originally claimed, the obvious calibration target fails on half of real
proxies, and a burst-based capacity probe reported full marks for a proxy that then lost
half its probes.
