# scanr documentation

Start with [getting-started.md](getting-started.md).

| | |
|---|---|
| [getting-started.md](getting-started.md) | install, first scan, verifying the record |
| [tutorial.md](tutorial.md) | learn it by using it: ten use cases with real output, and where nmap fits; the lab is [`tutorial/`](tutorial/) (`./lab up`) and `tests/tutorial.rs` keeps the document true |
| [cli.md](cli.md) | every command and flag, streams, exit codes (test-checked) |
| [configuration.md](configuration.md) | discovery, precedence, profiles (test-checked), targets, ports, DNS, labels |
| [transports.md](transports.md) | direct and SOCKS5; what a proxy can tell you; concurrency |
| [output-schema.md](output-schema.md) | the record, its guarantees, `jq` recipes (test-checked) |
| [tuning.md](tuning.md) | where the limits are, with numbers |
| [troubleshooting.md](troubleshooting.md) | keyed to emitted diagnostics |
| [security.md](security.md) | trust boundaries, credentials, DNS leakage, the one active probe, `unsafe` inventory (test-checked) |
| [stability.md](stability.md) | what 1.x promises and what it does not |
| [evidence.md](evidence.md) | every claim mapped to its test, corpus scenario or measurement (test-checked) |

Man pages are in [`../man/`](../man), generated from the CLI definition and test-checked;
`cargo run --example gen_man` regenerates them.

## Working on scanr

| | |
|---|---|
| [../ROADMAP.md](../ROADMAP.md) | what 1.0 promises and the phases to get there |
| [design/decisions.md](design/decisions.md) | decision register: decision, evidence, revisit trigger |
| [design/architecture.md](design/architecture.md) | module map, scheduler, writer, errors, dependencies |
| [../RELEASING.md](../RELEASING.md) | cutting a release |
