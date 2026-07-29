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
        BuiltinProfile {
            name: "proxy-careful",
            summary: "rotating pools, ssh -D, or any proxy whose limits you do not know",
            timing: Timing {
                concurrency: 64,
                rate: 50,
                proxy_connect_timeout: ms(5_000),
                handshake_timeout: ms(8_000),
                connect_timeout: ms(8_000),
                retries: 1,
                retry_delay: ms(500),
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
            },
        },
        BuiltinProfile {
            name: "direct-fast",
            summary: "LAN scanning where latency is known to be low",
            timing: Timing {
                concurrency: 2048,
                rate: 0,
                proxy_connect_timeout: ms(3_000),
                handshake_timeout: ms(5_000),
                connect_timeout: ms(1_000),
                retries: 0,
                retry_delay: ms(100),
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
#   built-ins: proxy-careful | proxy | direct | direct-fast
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


# ─── Transports ──────────────────────────────────────────────────────────────
# How connections are established. One transport per scan.

# The implicit direct transport always exists; redefining it is optional.
[transports.direct]
type = "direct"

[transports.lab]
# "direct" or "socks5". SOCKS4/4a are not supported: they define only four reply
# codes and cannot distinguish a closed port from a filtered one.
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

    #[test]
    fn template_documents_every_profile_field() {
        // The other drift direction: a field added to RawProfile but not documented.
        for field in [
            "concurrency",
            "rate",
            "proxy_connect_timeout",
            "handshake_timeout",
            "connect_timeout",
            "retries",
            "retry_delay",
        ] {
            assert!(
                ANNOTATED_TEMPLATE.contains(&format!("\n{field} = ")),
                "template is missing an entry for profile field `{field}`"
            );
        }
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
        assert_eq!(profiles.len(), 4);
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
