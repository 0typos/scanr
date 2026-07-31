# scanr documentation

The [README](../README.md) covers what the tool is and why. For a first session from
install to a verified record, start with **[getting-started.md](getting-started.md)**.

## Guides

| | |
|---|---|
| [getting-started.md](getting-started.md) | Install, first scan, and checking the result |
| [configuration.md](configuration.md) | File discovery, precedence, profiles, target and port sets, DNS modes |
| [transports.md](transports.md) | Direct and SOCKS5, what your proxy can actually tell you, concurrency it will take |
| [output-schema.md](output-schema.md) | The scan record, its guarantees, and `jq` recipes |
| [tuning.md](tuning.md) | Where the real limits are, with measured numbers |
| [troubleshooting.md](troubleshooting.md) | Keyed to the diagnostics the tool actually emits |
| [security.md](security.md) | Trust boundaries, credentials, DNS leakage, authorization |

Man pages are in [`../man/`](../man), one per command, generated from the CLI definition
and checked by a test so they cannot drift. `cargo run --example gen_man` regenerates them.

Release process is in [RELEASING.md](../RELEASING.md).

## Design records

`design/` holds what was decided before and during implementation. Worth reading if you
are changing the tool, or if you want to know why it does not do something.

| | |
|---|---|
| [00-product-brief.md](design/00-product-brief.md) | The problem, the users, and the non-goals |
| [01-decision-register.md](design/01-decision-register.md) | Every significant decision with alternatives, rationale, and revisit trigger |
| [02-runtime-evaluation.md](design/02-runtime-evaluation.md) | Why blocking threads rather than `mio` or Tokio, with the measurements |
| [03-architecture.md](design/03-architecture.md) | Module boundaries, scheduler, writer, error model, dependency rationale |
| [04-config-spec.md](design/04-config-spec.md) | Configuration schema and resolution |
| [05-jsonl-spec.md](design/05-jsonl-spec.md) | Record format, invariants, event catalogue |
| [06-cli-spec.md](design/06-cli-spec.md) | Command tree, override allowlist, exit codes |
| [07-milestones.md](design/07-milestones.md) | Implementation plan as executed |
| [08-release-plan.md](design/08-release-plan.md) | What remains before a release, and what is deferred |
| [09-review-2026-07.md](design/09-review-2026-07.md) | Post-publication review: findings, evidence, and the plan to address them |

The decision register is the one to read first. It records the assumptions that turned out
to be **wrong** as prominently as the ones that held — `ssh -D` does not collapse reply
codes the way the docs originally claimed, the obvious calibration target fails on half of
real proxies, and a burst-based capacity probe reported full marks for a proxy that then
lost half its probes.
