//! Built-in profiles and the annotated configuration template.
//!
//! Profiles are flat and complete — no inheritance (rejected for v1). Every value is a
//! real configuration field with a visible number; nothing here triggers undocumented
//! internal behaviour.

use std::time::Duration;

use crate::plan::types::Timing;

pub struct BuiltinProfile {
    pub name: &'static str,
    pub summary: &'static str,
    pub timing: Timing,
}

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub fn builtin_profiles() -> Vec<BuiltinProfile> {
    vec![
        // ── ssh -D ──────────────────────────────────────────────────────────
        //
        // `ssh -D` differs from a normal SOCKS5 proxy in three ways that matter, all
        // measured against OpenSSH 10.2p1:
        //
        // * **The listener is local.** Every probe connects to 127.0.0.1, which
        //   `tcp_tw_reuse = 2` exempts from TIME_WAIT reuse, so the ~470/s ephemeral
        //   ceiling behind `proxy`'s `rate = 400` simply does not apply. Capping the
        //   rate here throttles the scan for nothing: 2,000 probes took 5.00 s under
        //   that cap and 0.07 s without it.
        // * **The local round trip is free.** SOCKS negotiation measured 0.4–0.5 ms, so
        //   the multi-second `proxy_connect_timeout` and `handshake_timeout` the proxy
        //   profiles carry are covering a network that is not there. Only the
        //   destination connect crosses the wire.
        // * **Concurrency saturates early and then hurts.** A single TCP connection
        //   carries every channel. Throughput was flat at ~28,500 probes/s from
        //   concurrency 32 to 128, then fell off a cliff at 160 — reproducibly, three
        //   runs at each level. The cliff is a fixed ~1 s stall rather than a slower
        //   rate: at concurrency 160, 2,000 / 4,000 / 8,000 probes all cost ~1.1 s.
        //   Nothing above ~128 buys throughput, and it risks the stall.
        //
        // Concurrency across the three is chosen to cover round-trip delay rather than
        // to be "careful": in-flight probes needed is roughly rate x RTT, so a *slower*
        // link wants *more* in flight, not less — bounded by the measured cliff.
        //
        // A refused destination costs nothing (0.4 ms — `ssh -D` closes the channel with
        // no reply), so `connect_timeout` is only ever paid by genuinely silent hosts.
        BuiltinProfile {
            name: "ssh-fast",
            summary: "ssh -D to a nearby server (LAN, same DC), latency known low",
            timing: Timing {
                concurrency: 64,
                rate: 0,
                proxy_connect_timeout: ms(1_000),
                handshake_timeout: ms(3_000),
                connect_timeout: ms(2_000),
                retries: 0,
                retry_delay: ms(250),
                banner: None,
            },
        },
        BuiltinProfile {
            name: "ssh",
            summary: "ssh -D over a typical internet link",
            timing: Timing {
                concurrency: 96,
                rate: 0,
                proxy_connect_timeout: ms(2_000),
                handshake_timeout: ms(5_000),
                connect_timeout: ms(6_000),
                retries: 1,
                retry_delay: ms(500),
                banner: None,
            },
        },
        BuiltinProfile {
            name: "ssh-slow",
            summary: "ssh -D over a high-latency, congested, or long-haul link",
            timing: Timing {
                // More in flight to cover the round trip, still under the measured cliff.
                concurrency: 128,
                rate: 0,
                proxy_connect_timeout: ms(3_000),
                handshake_timeout: ms(10_000),
                connect_timeout: ms(15_000),
                retries: 1,
                retry_delay: ms(1_000),
                banner: None,
            },
        },
        BuiltinProfile {
            name: "proxy-careful",
            summary: "rotating pools, or any proxy whose limits you do not know",
            timing: Timing {
                concurrency: 64,
                rate: 50,
                proxy_connect_timeout: ms(5_000),
                handshake_timeout: ms(8_000),
                connect_timeout: ms(8_000),
                retries: 1,
                retry_delay: ms(500),
                banner: None,
            },
        },
        BuiltinProfile {
            name: "proxy",
            summary: "self-hosted SOCKS5 (dante, microsocks) on a known-good link",
            timing: Timing {
                concurrency: 512,
                // Below the ~470/s ephemeral ceiling that applies to a remote proxy.
                rate: 400,
                proxy_connect_timeout: ms(3_000),
                handshake_timeout: ms(5_000),
                connect_timeout: ms(5_000),
                retries: 1,
                retry_delay: ms(250),
                banner: None,
            },
        },
        BuiltinProfile {
            name: "direct",
            summary: "routed networks with no proxy in the path",
            timing: Timing {
                concurrency: 512,
                rate: 0,
                proxy_connect_timeout: ms(3_000),
                handshake_timeout: ms(5_000),
                connect_timeout: ms(2_000),
                retries: 1,
                retry_delay: ms(250),
                banner: None,
            },
        },
        // A short timeout is only safe when something else covers a lost SYN.
        //
        // TCP's initial retransmission timeout is about one second (RFC 6298, Linux
        // `TCP_TIMEOUT_INIT`), so a *single* attempt with a sub-second budget gives up
        // before the first retransmit: one dropped SYN — routine on wifi — silently
        // becomes `filtered`, and a missed open port is the worst answer this tool can
        // give. The previous shape here, a 1s timeout with `retries: 0`, sat exactly in
        // that trap.
        //
        // A retry is a *fresh* SYN rather than a longer wait, which is the cheaper way
        // to survive loss. 300ms twice beats 1s once on both axes: measured 9.22s
        // against 13.13s over an unresponsive /24 x 100 ports, and two independent
        // chances instead of one.
        //
        // Still a LAN profile. On a path whose round trip genuinely exceeds 300ms both
        // attempts fail and the host is reported filtered — use `direct` there, which is
        // why its 2s default is not being shortened to match.
        BuiltinProfile {
            name: "direct-fast",
            summary: "LAN scanning where round-trip latency is known to be under ~100ms",
            timing: Timing {
                concurrency: 2048,
                rate: 0,
                proxy_connect_timeout: ms(3_000),
                handshake_timeout: ms(5_000),
                connect_timeout: ms(300),
                retries: 1,
                retry_delay: ms(100),
                banner: None,
            },
        },
    ]
}

pub fn builtin_profile(name: &str) -> Option<BuiltinProfile> {
    builtin_profiles().into_iter().find(|p| p.name == name)
}

pub fn builtin_profile_names() -> Vec<&'static str> {
    builtin_profiles().into_iter().map(|p| p.name).collect()
}

/// Defaults when nothing selects a profile. Which one applies follows the transport:
/// a proxied scan wants the conservative proxy timings, while a direct scan should not
/// inherit the proxy profile's rate limit.
pub const DEFAULT_PROXY_PROFILE: &str = "proxy";
pub const DEFAULT_DIRECT_PROFILE: &str = "direct";
pub const DEFAULT_TRANSPORT: &str = "direct";
pub const DEFAULT_OUTPUT_DIR: &str = "./scanr-results";

/// Written by `scanr config init`. Every field appears with its default, its range, and
/// whether the CLI may override it.
///
/// A test asserts this parses cleanly against the real config types, so a field that is
/// renamed in code but not here fails the build rather than drifting silently.
pub const ANNOTATED_TEMPLATE: &str = r##"# scanr configuration
#
# Discovery, lowest precedence first:
#   1. ~/.config/scanr/config.toml   (or $XDG_CONFIG_HOME/scanr/config.toml)
#   2. ./scanr.toml                  (searched upward from the working directory)
# `--config <path>` replaces both.
#
# Resolution order for any single value:
#   builtin default -> builtin profile -> user config -> project config
#     -> selected profile -> named scan -> environment (credentials) -> CLI override
#
# `scanr plan <scan>` shows the final value of every field and where it came from.

version = 1


# ─── Defaults ────────────────────────────────────────────────────────────────
# Applied when a scan does not specify its own.
[defaults]
# Profile to use when a scan does not name one. Leave it unset and scanr follows the
# transport: `proxy` for a SOCKS5 transport, `direct` otherwise. Set it to pin one.
#   built-ins: ssh-fast | ssh | ssh-slow | proxy-careful | proxy | direct | direct-fast
#   default: follows the transport      CLI: --profile
# profile = "proxy"

# Transport to use when a scan does not name one.
#   default: "direct"         CLI: --transport
transport = "direct"

# Where JSONL scan records are written. Created if absent.
#   default: "./scanr-results"    CLI: --output-dir
output_dir = "./scanr-results"

# Print only open ports to stdout. The JSONL record always contains every probe
# outcome regardless of this setting.
#   default: true             CLI: --open-only / --all
open_only = true

# gzip the record. Written as concatenated gzip members, so `zcat` and `zless` read it
# and a killed scan still decodes up to its last flushed frame.
#   default: true             CLI: --compress / --no-compress
compress = true

# Collapse repeated outcomes into `probe_span` events instead of one row per probe. A
# large scan is mostly identical `filtered` rows; spans take that from hundreds of MB to
# kilobytes. `open` and `error` results always keep their own row.
#   default: true             CLI: --spans / --no-spans
spans = true

# Read what an open service volunteers on connect, without sending anything. Only
# services that greet first say anything — SSH, SMTP, FTP, POP3, IMAP, MySQL. HTTP and
# anything behind TLS greet nobody, so an empty banner means "said nothing unprompted".
#   default: true             CLI: --banner / --no-banner
banner = true

# A file of `name port/proto` lines to label ports from, consulted ahead of
# /etc/services and the built-in table. `~` is expanded.
#   default: unset
# services_file = "~/.config/scanr/services"

# Read /etc/services for port labels. Set false for labels that depend only on this
# config and the binary, and so match on every machine.
#   default: true
use_etc_services = true


# ─── Profiles ────────────────────────────────────────────────────────────────
# Timing and concurrency. Flat and complete — profiles do not inherit from each
# other, so what you read here is exactly what runs.
#
# Defining a profile with a built-in name overrides only the fields you set.
[profiles.lab]
# In-flight probes. This is also the worker thread count: there is no queue, so
# concurrency is a hard ceiling rather than a target.
# Note that higher is not always faster — measured throughput peaked near 512 and
# declined at 2048.
#   range: 1-65535            default: profile-dependent    CLI: --concurrency
concurrency = 512

# Launch rate ceiling in probes/second. 0 disables the limit.
#
# Through a *remote* proxy every probe consumes a local ephemeral port, and Linux
# holds TIME_WAIT for 60s against a default range of 28,232 ports — a hard ceiling
# near 470/s. scanr closes probe sockets with SO_LINGER{on,0} to avoid TIME_WAIT
# entirely, which lifts that ceiling substantially, but the limit is still worth
# setting when you do not own the proxy.
#   range: 0-1000000          default: profile-dependent    CLI: --rate
rate = 400

# Time to establish the TCP connection to the proxy itself. Ignored for direct.
#   default: "3s"             CLI: (none)
proxy_connect_timeout = "3s"

# Time for the SOCKS5 greeting, authentication, and CONNECT reply. Ignored for direct.
#   default: "5s"             CLI: (none)
handshake_timeout = "5s"

# Time for the destination connection to complete. For a proxied scan this covers
# the proxy's own attempt to reach the destination.
#   default: profile-dependent    CLI: --connect-timeout
connect_timeout = "5s"

# Retries for probes that time out. Other outcomes are never retried: a refused
# connection is a definitive answer, whereas a timeout is ambiguous between a slow
# proxy and a filtered destination.
# Each retried probe still produces exactly one result record, carrying `attempts`
# and `attempt_states`.
#   range: 0-10               default: 1                    CLI: --retries
retries = 1

# Delay before a retry.
#   default: "250ms"          CLI: (none)
retry_delay = "250ms"

# Most bytes to read from a banner. Truncation is recorded, never silent.
#   range: 1-4096             default: 1024                 CLI: (none)
banner_bytes = 1024

# Ceiling on the wait for a greeting, not the wait itself. A greeting arrives about one
# round trip after connect, so the actual wait scales off this host's measured connect
# time and only approaches the ceiling on genuinely slow paths. It still matters:
# concurrency is the worker-thread count with no queue, so a worker waiting on a silent
# port is a worker issuing no probes.
#   default: "500ms"          CLI: (none)
banner_timeout = "500ms"


# ─── Transports ──────────────────────────────────────────────────────────────
# How connections are established. One transport per scan.

# The implicit direct transport always exists; redefining it is optional.
[transports.direct]
type = "direct"

[transports.lab]
# "direct", "socks5", "chain" or "pool". SOCKS4/4a are not supported: they define only
# four reply codes and cannot distinguish a closed port from a filtered one.
type = "socks5"

# host:port of the proxy. Required for socks5.
address = "127.0.0.1:1080"

# Optional SOCKS5 username/password authentication (RFC 1929). Left commented so
# this file works as generated; uncomment both lines to enable it.
# Note that this authenticates you to the proxy; it does not encrypt anything.
#
# Credentials come from the environment or a file — never inline. An inline
# `password` key is rejected, because project config is normally committed.
#   password_file must be mode 0600 or narrower.
# username     = "scanner"
# password_env = "SCANR_LAB_PASSWORD"
# password_file = "~/.config/scanr/lab.password"

# Who resolves hostnames.
#   auto       transport-side when the transport supports it, local otherwise
#   transport  hand the hostname to the proxy unresolved (no local DNS leak)
#   local      resolve here; names with several addresses become several targets
#   disabled   reject hostname targets outright
#
# Under transport-side resolution the SOCKS5 reply carries the proxy's bound
# address, not the destination's, so results cannot record which IP was probed.
# That is the tradeoff for not leaking queries and for reaching split-horizon names.
#   default: "auto"           CLI: --dns
dns = "auto"

# What this proxy can actually distinguish, as reported by
# `scanr transport test lab`. Many proxies — ssh -D and most commercial pools —
# collapse every failure into SOCKS5 reply 0x01, so a closed port and a filtered
# one are indistinguishable through them.
#   full       refused connections are reported distinctly (reply 0x05)
#   open_only  every failure looks the same; non-open results are recorded as
#              `error` rather than guessed into closed/filtered
# Leave it unset and scanr warns on every scan that fidelity is unknown.
#   default: unset            CLI: (none)
# fidelity = "full"

# A chain traverses SOCKS5 transports in order, each reached through the one before it,
# so the destination sees only the last. Every hop must be socks5. Latency is the sum of
# the hops, and the chain's fidelity is its weakest hop's.
# [transports.doubled]
# type = "chain"
# hops = ["lab", "exit-b"]

# A pool probes *across* its members rather than through them, which multiplies both the
# local ephemeral-port ceiling and the per-proxy connection cap. Members are assigned by
# hashing the endpoint, so a given endpoint always goes via the same member and a rerun
# reproduces. It is not failover: a member that is down fails its share of the work
# rather than having it taken over, and the record names the member behind every result.
# [transports.spread]
# type = "pool"
# members = ["lab", "exit-b", "exit-c"]


# ─── Target sets ─────────────────────────────────────────────────────────────
# Named, reusable. Accepts IP literals, CIDR blocks, inclusive a-b ranges, and
# hostnames. IPv4 CIDRs include their network and broadcast addresses.
[targets.lab]
include = [
  "10.20.30.0/24",
  "10.20.31.10-10.20.31.20",
]
# Applied after expansion. Useful for keeping gateways and monitoring hosts out.
exclude = [
  "10.20.30.1",
  "10.20.30.254",
]

# A set may instead read a line-delimited file. Blank lines and `#` comments skipped.
[targets.from-inventory]
file = "hosts.txt"


# ─── Port sets ───────────────────────────────────────────────────────────────
# Accepts single ports, inclusive ranges, and the keyword "all" (1-65535).
[ports.web]
ports = ["80", "443", "8000-8999"]

[ports.common]
ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"


# ─── Scans ───────────────────────────────────────────────────────────────────
# Named, runnable with `scanr run <name>`.
[scans.internal-web]
description = "Internal web services through the lab proxy"
profile = "proxy"
transport = "lab"

# Names defined above under [targets.*] and [ports.*]. A value that matches no
# defined set is parsed as a literal spec, so `targets = ["10.0.0.0/24"]` also works.
targets = ["lab"]
ports = ["web"]

# Any profile field may be overridden inline for this scan alone.
connect_timeout = "8s"
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::raw::RawConfig;

    #[test]
    fn template_parses_against_real_types() {
        // deny_unknown_fields means a field renamed in code but not here fails here.
        let cfg: RawConfig = toml::from_str(ANNOTATED_TEMPLATE)
            .expect("annotated template must deserialize against the current config types");
        assert_eq!(cfg.version, Some(1));
    }

    /// The other drift direction: a field added to `RawProfile` but not documented.
    ///
    /// The destructuring is the guard. A new field on `RawProfile` stops this compiling
    /// until someone names it here, which is the only way to notice a key the parser
    /// accepts and `config init` never mentions — nothing else fails when the two
    /// disagree, and the config file is the whole interface for a reproducible run. Nine
    /// keys had drifted out of the template before this was written.
    #[test]
    fn template_documents_every_profile_field() {
        let crate::config::raw::RawProfile {
            concurrency,
            rate,
            proxy_connect_timeout,
            handshake_timeout,
            connect_timeout,
            retries,
            retry_delay,
            banner_bytes,
            banner_timeout,
        } = crate::config::raw::RawProfile::default();
        // Named so the bindings are used and a typo above cannot silently pass.
        let fields = [
            ("concurrency", concurrency.is_none()),
            ("rate", rate.is_none()),
            ("proxy_connect_timeout", proxy_connect_timeout.is_none()),
            ("handshake_timeout", handshake_timeout.is_none()),
            ("connect_timeout", connect_timeout.is_none()),
            ("retries", retries.is_none()),
            ("retry_delay", retry_delay.is_none()),
            ("banner_bytes", banner_bytes.is_none()),
            ("banner_timeout", banner_timeout.is_none()),
        ];
        for (field, _) in fields {
            assert!(
                ANNOTATED_TEMPLATE.contains(&format!("\n{field} = ")),
                "template is missing an entry for profile field `{field}`"
            );
        }
    }

    /// Same guard for `[defaults]`. Five keys had drifted out of the template.
    #[test]
    fn template_documents_every_defaults_field() {
        let crate::config::raw::RawDefaults {
            profile,
            transport,
            output_dir,
            open_only,
            compress,
            spans,
            banner,
            services_file,
            use_etc_services,
        } = crate::config::raw::RawDefaults::default();
        let fields = [
            ("profile", profile.is_none()),
            ("transport", transport.is_none()),
            ("output_dir", output_dir.is_none()),
            ("open_only", open_only.is_none()),
            ("compress", compress.is_none()),
            ("spans", spans.is_none()),
            ("banner", banner.is_none()),
            ("services_file", services_file.is_none()),
            ("use_etc_services", use_etc_services.is_none()),
        ];
        for (field, _) in fields {
            assert!(
                template_mentions(field),
                "template is missing an entry for defaults field `{field}`"
            );
        }
    }

    /// Same guard for a transport. `hops` and `members` had drifted out, which meant
    /// `config init` documented no way to reach either of the two transport types added
    /// after it was written.
    #[test]
    fn template_documents_every_transport_field() {
        let crate::config::raw::RawTransport {
            kind,
            address,
            username,
            password_env,
            password_file,
            password,
            dns,
            fidelity,
            hops,
            members,
        } = crate::config::raw::RawTransport::default();
        assert!(
            password.is_none(),
            "an inline password is rejected, not documented (D14)"
        );
        let fields = [
            ("type", kind.is_none()),
            ("address", address.is_none()),
            ("username", username.is_none()),
            ("password_env", password_env.is_none()),
            ("password_file", password_file.is_none()),
            ("dns", dns.is_none()),
            ("fidelity", fidelity.is_none()),
            ("hops", hops.is_none()),
            ("members", members.is_none()),
        ];
        for (field, _) in fields {
            assert!(
                template_mentions(field),
                "template is missing an entry for transport field `{field}`"
            );
        }
    }

    /// A key counts as documented whether it is live or commented out, since several are
    /// deliberately shown commented so the generated file works as-is.
    fn template_mentions(field: &str) -> bool {
        ANNOTATED_TEMPLATE.lines().any(|l| {
            let t = l.trim_start().trim_start_matches('#').trim_start();
            // Split on `=` rather than matching a literal, because the template aligns
            // some values with runs of spaces.
            t.split_once('=')
                .is_some_and(|(k, _)| k.trim_end() == field)
        })
    }

    #[test]
    fn template_internal_references_resolve() {
        let cfg: RawConfig = toml::from_str(ANNOTATED_TEMPLATE).unwrap();
        let scan = &cfg.scans["internal-web"];
        let t = scan.transport.as_deref().unwrap();
        assert!(cfg.transports.contains_key(t), "transport `{t}` undefined");
        for name in scan.targets.as_ref().unwrap().items() {
            assert!(
                cfg.targets.contains_key(&name),
                "target set `{name}` undefined"
            );
        }
        for name in scan.ports.as_ref().unwrap().items() {
            assert!(cfg.ports.contains_key(&name), "port set `{name}` undefined");
        }
    }

    #[test]
    fn template_contains_no_inline_password() {
        // D14: the template must not model the thing we reject.
        for line in ANNOTATED_TEMPLATE.lines() {
            let t = line.trim();
            assert!(
                !(t.starts_with("password =") || t.starts_with("password=")),
                "template contains an inline password: {line}"
            );
        }
    }

    #[test]
    fn builtin_profiles_are_distinct_and_sane() {
        let profiles = builtin_profiles();
        assert_eq!(profiles.len(), 7);
        for p in &profiles {
            assert!(p.timing.concurrency >= 1, "{}", p.name);
            assert!(p.timing.retries <= 10, "{}", p.name);
            assert!(!p.summary.is_empty(), "{}", p.name);
        }
        let names = builtin_profile_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate built-in profile name");
    }

    #[test]
    fn proxy_profiles_stay_under_the_ephemeral_ceiling() {
        // ~470/s is the sustained limit against a remote proxy without SO_LINGER.
        for name in ["proxy", "proxy-careful"] {
            let p = builtin_profile(name).unwrap();
            assert!(
                p.timing.rate > 0 && p.timing.rate <= 470,
                "{name} rate {} should be capped near the ephemeral budget",
                p.timing.rate
            );
        }
    }

    /// The `ssh -D` listener is on loopback, which `tcp_tw_reuse = 2` exempts from the
    /// TIME_WAIT reuse restriction, so the ephemeral ceiling that justifies `proxy`'s
    /// rate cap does not apply. Measured: 4,000 probes took 80 s under `proxy-careful`
    /// (rate 50) and 0.16 s under `ssh`, with every probe reported either way.
    #[test]
    fn ssh_profiles_are_not_rate_capped() {
        for name in ["ssh", "ssh-fast", "ssh-slow"] {
            let p = builtin_profile(name).unwrap();
            assert_eq!(
                p.timing.rate, 0,
                "{name} must not inherit the remote-proxy ephemeral cap"
            );
        }
    }

    /// Throughput through one multiplexed SSH connection was flat from concurrency 32 to
    /// 128 and fell off a reproducible cliff at 160 (OpenSSH 10.2p1). Nothing above that
    /// buys throughput, so no `ssh` profile may wander past it.
    #[test]
    fn ssh_profiles_stay_below_the_measured_concurrency_cliff() {
        for name in ["ssh", "ssh-fast", "ssh-slow"] {
            let p = builtin_profile(name).unwrap();
            assert!(
                (1..=128).contains(&p.timing.concurrency),
                "{name} concurrency {} is past the measured cliff",
                p.timing.concurrency
            );
        }
    }

    /// The local SOCKS round trip measured 0.4-0.5 ms, so the multi-second local
    /// timeouts the proxy profiles carry are covering a network that is not there.
    #[test]
    fn ssh_profiles_do_not_wait_seconds_on_a_local_socket() {
        for name in ["ssh", "ssh-fast", "ssh-slow"] {
            let p = builtin_profile(name).unwrap();
            assert!(
                p.timing.proxy_connect_timeout <= ms(3_000),
                "{name} waits {:?} to reach a loopback listener",
                p.timing.proxy_connect_timeout
            );
            // The destination connect is the only leg that crosses the wire, so it is
            // the one that should dominate.
            assert!(
                p.timing.connect_timeout >= p.timing.proxy_connect_timeout,
                "{name}: the local leg should not outlast the remote one"
            );
        }
    }

    /// A sub-second timeout must be paired with a retry.
    ///
    /// TCP's initial RTO is about a second, so a single attempt below that gives up
    /// before the first SYN retransmit and turns one dropped packet into a missed open
    /// port. `direct-fast` used to be 1s with no retry, which is that trap.
    #[test]
    fn a_short_timeout_always_has_a_second_chance() {
        for p in builtin_profiles() {
            if p.timing.connect_timeout < ms(1_000) {
                assert!(
                    p.timing.retries >= 1,
                    "{}: {:?} is under TCP's initial RTO, so it needs a retry to survive \
                     a dropped SYN",
                    p.name,
                    p.timing.connect_timeout
                );
            }
        }
    }

    #[test]
    fn direct_profiles_are_unlimited_by_default() {
        for name in ["direct", "direct-fast"] {
            assert_eq!(builtin_profile(name).unwrap().timing.rate, 0);
        }
    }

    #[test]
    fn default_profiles_exist() {
        assert!(builtin_profile(DEFAULT_PROXY_PROFILE).is_some());
        assert!(builtin_profile(DEFAULT_DIRECT_PROFILE).is_some());
    }

    #[test]
    fn unknown_profile_is_none() {
        assert!(builtin_profile("turbo").is_none());
    }
}
