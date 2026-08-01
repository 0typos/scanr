//! A pool of proxies, probed across rather than through.
//!
//! Two things a pool buys, and one it does not.
//!
//! **Local ephemeral ports.** Every probe through a remote proxy consumes a local port
//! for 60 seconds of `TIME_WAIT`, which caps a single remote proxy near 470 probes/sec
//! (D9). That budget is per *four-tuple*, not per host — a port in `TIME_WAIT` against
//! proxy A is still available against proxy B — so distinct proxy addresses multiply the
//! ceiling roughly linearly.
//!
//! **Proxy connection caps.** A proxy's own `maxconn` is usually what binds first: a
//! stock 3proxy loses 48% of probes at concurrency 64 (see `transport test --calibrate`).
//! N proxies give you N of those budgets.
//!
//! **Not resilience.** A member that is down fails its share of the work rather than
//! having it taken over. Assignment is deterministic (below), which is the property that
//! makes a scan reproducible, and failover is the opposite of deterministic. The record
//! names the member behind every result, so a bad one is visible rather than inferred.

use std::sync::Arc;

use super::{Destination, Transport};
use crate::plan::types::{Fidelity, Timing};
use crate::probe::ProbeOutcome;

pub struct PoolTransport {
    name: String,
    members: Vec<Box<dyn Transport>>,
    /// One handle per member, cloned onto each result. Built here rather than per probe:
    /// `Arc::from(name.to_string())` on the hot path allocated a fresh `String` *and* a
    /// fresh `Arc` for every probe, which is the opposite of what an `Arc` is for.
    labels: Vec<Arc<str>>,
    /// The weakest member's fidelity — see [`PoolTransport::new`].
    fidelity: Fidelity,
}

impl PoolTransport {
    /// Panics on an empty member list, which the resolver refuses.
    pub fn new(name: String, members: Vec<Box<dyn Transport>>) -> Self {
        assert!(!members.is_empty(), "a pool needs at least one member");
        // The weakest link, because a result is only as trustworthy as the member that
        // produced it and a caller reading the transport's fidelity has not yet seen
        // which one that was. Per-result truth is finer than this: each row records its
        // own member, and a `closed` from a faithful member is still a real `closed`.
        let fidelity = members
            .iter()
            .map(|m| m.fidelity())
            .fold(Fidelity::Full, Fidelity::weakest);
        let labels = members.iter().map(|m| Arc::from(m.name())).collect();
        Self {
            name,
            members,
            labels,
            fidelity,
        }
    }

    /// Which member handles an endpoint.
    ///
    /// Hashed from the endpoint rather than round-robined, so the same endpoint goes via
    /// the same member on every run. A scan that reports `10.0.0.5:443` as filtered can
    /// then be re-run and land on the same proxy, which is the difference between
    /// reproducing a result and rolling the dice again.
    ///
    /// FNV-1a rather than `DefaultHasher`: the standard hasher is explicitly not stable
    /// across releases, and an assignment that silently changes under a toolchain upgrade
    /// would break exactly the property this exists for.
    fn pick(&self, dest: &Destination) -> usize {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |b: u8| {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        };
        match dest {
            Destination::Addr(a) => {
                match a.ip() {
                    std::net::IpAddr::V4(v4) => v4.octets().iter().for_each(|b| eat(*b)),
                    std::net::IpAddr::V6(v6) => v6.octets().iter().for_each(|b| eat(*b)),
                }
                a.port().to_be_bytes().iter().for_each(|b| eat(*b));
            }
            Destination::Host(name, port) => {
                name.as_bytes().iter().for_each(|b| eat(*b));
                port.to_be_bytes().iter().for_each(|b| eat(*b));
            }
        }
        (h % self.members.len() as u64) as usize
    }
}

impl Transport for PoolTransport {
    fn probe(&self, dest: &Destination, timing: &Timing) -> ProbeOutcome {
        let i = self.pick(dest);
        let mut o = self.members[i].probe(dest, timing);
        // Only if nothing deeper already claimed it. A pool of pools would otherwise
        // overwrite the inner member's name with the container's, so the record would
        // name a bag of proxies rather than the proxy that answered.
        if o.via.is_none() {
            o.via = Some(self.labels[i].clone());
        }
        o
    }

    /// Only if *every* member does. A pool that resolves names on some hops and not
    /// others would resolve them differently depending on the endpoint, which is a
    /// difference nothing downstream could see.
    fn supports_remote_dns(&self) -> bool {
        self.members.iter().all(|m| m.supports_remote_dns())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn type_name(&self) -> &'static str {
        "pool"
    }

    fn fidelity(&self) -> Fidelity {
        self.fidelity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Phases, Source, State};
    use std::net::SocketAddr;

    /// A member that only reports its own name, so a test can see which one answered.
    struct Marker {
        name: String,
        fidelity: Fidelity,
    }

    impl Transport for Marker {
        fn probe(&self, _d: &Destination, _t: &Timing) -> ProbeOutcome {
            ProbeOutcome::open(Phases::default(), Source::ProxyReply)
        }
        fn supports_remote_dns(&self) -> bool {
            true
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn type_name(&self) -> &'static str {
            "socks5"
        }
        fn fidelity(&self) -> Fidelity {
            self.fidelity
        }
    }

    fn pool(fidelities: &[Fidelity]) -> PoolTransport {
        PoolTransport::new(
            "pool".into(),
            fidelities
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    Box::new(Marker {
                        name: format!("p{i}"),
                        fidelity: *f,
                    }) as Box<dyn Transport>
                })
                .collect(),
        )
    }

    fn addr(s: &str) -> Destination {
        Destination::Addr(s.parse::<SocketAddr>().unwrap())
    }

    /// The property that keeps a pooled scan reproducible.
    #[test]
    fn an_endpoint_always_goes_to_the_same_member() {
        let p = pool(&[Fidelity::Full; 4]);
        for e in ["10.0.0.1:22", "10.0.0.1:443", "192.168.1.9:80", "[::1]:22"] {
            let first = p.pick(&addr(e));
            for _ in 0..50 {
                assert_eq!(p.pick(&addr(e)), first, "{e} moved between members");
            }
        }
    }

    /// ...and a different port on the same host is a different endpoint, or a pool would
    /// send every port of a host down one proxy and defeat its own purpose.
    #[test]
    fn work_is_spread_across_the_members() {
        let p = pool(&[Fidelity::Full; 4]);
        let mut hit = [0usize; 4];
        for port in 1..=2000u16 {
            hit[p.pick(&addr(&format!("10.0.0.1:{port}")))] += 1;
        }
        for (i, n) in hit.iter().enumerate() {
            assert!(*n > 300, "member {i} got only {n} of 2000 — poor spread");
        }
    }

    /// A result is only as trustworthy as the weakest member a caller might have hit,
    /// and the transport-level number is read before anyone knows which one that was.
    #[test]
    fn the_pool_reports_its_weakest_member() {
        assert_eq!(pool(&[Fidelity::Full; 3]).fidelity(), Fidelity::Full);
        assert_eq!(
            pool(&[Fidelity::Full, Fidelity::OpenOnly]).fidelity(),
            Fidelity::OpenOnly
        );
        assert_eq!(
            pool(&[Fidelity::Full, Fidelity::Unknown]).fidelity(),
            Fidelity::Unknown
        );
    }

    /// A pool of pools must name the proxy that answered, not the bag it was in.
    #[test]
    fn a_nested_pool_keeps_the_inner_members_name() {
        let inner = PoolTransport::new(
            "inner".into(),
            vec![Box::new(Marker {
                name: "exit-b".into(),
                fidelity: Fidelity::Full,
            })],
        );
        let outer = PoolTransport::new("outer".into(), vec![Box::new(inner)]);
        let o = outer.probe(
            &addr("10.0.0.7:443"),
            &crate::plan::types::Timing::for_test(),
        );
        assert_eq!(
            o.via.as_deref(),
            Some("exit-b"),
            "the outer pool must not overwrite what answered"
        );
    }

    /// Which member answered has to survive into the result, or a single bad proxy in a
    /// pool is invisible: its results look like the network's fault.
    #[test]
    fn the_result_names_the_member_that_produced_it() {
        let p = pool(&[Fidelity::Full; 3]);
        let d = addr("10.0.0.7:443");
        let expected = format!("p{}", p.pick(&d));
        let o = p.probe(&d, &crate::plan::types::Timing::for_test());
        assert_eq!(o.state, State::Open);
        assert_eq!(o.via.as_deref(), Some(expected.as_str()));
    }
}
