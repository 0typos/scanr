pub mod human;
pub mod jsonl;
pub mod span;

use std::net::IpAddr;

use crate::probe::{ProbeOutcome, State};

pub use human::{Progress, ResultPrinter, Style};
pub use jsonl::{Counts, JsonlWriter, SCHEMA_VERSION, new_scan_id};
pub use span::Spans;

/// One completed probe, retries already merged (D10).
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub probe_index: u64,
    pub target: String,
    /// `None` for hostname targets under transport-side DNS: the SOCKS5 reply carries
    /// the proxy's bound address, not the destination's (D15).
    pub resolved_address: Option<IpAddr>,
    pub port: u16,
    pub outcome: ProbeOutcome,
    pub attempts: u32,
    pub attempt_states: Vec<State>,
}

impl ProbeRecord {
    pub fn to_json(&self) -> serde_json::Value {
        let phases = &self.outcome.phases;
        let ms = |d: Option<std::time::Duration>| {
            d.map(|d| (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0)
        };
        let mut timing = serde_json::Map::new();
        if let Some(v) = ms(phases.proxy_connect) {
            timing.insert("proxy_connect".into(), serde_json::json!(v));
        }
        if let Some(v) = ms(phases.handshake) {
            timing.insert("handshake".into(), serde_json::json!(v));
        }
        if let Some(v) = ms(phases.connect) {
            timing.insert("connect".into(), serde_json::json!(v));
        }
        timing.insert(
            "total".into(),
            serde_json::json!(ms(Some(phases.total)).unwrap_or(0.0)),
        );

        serde_json::json!({
            "probe_index": self.probe_index,
            "target": self.target,
            "resolved_address": self.resolved_address.map(|a| a.to_string()),
            "port": self.port,
            "protocol": "tcp",
            "state": self.outcome.state.as_str(),
            "source": self.outcome.source.as_str(),
            "reason": self.outcome.reason,
            "service_label": crate::probe::service_label(self.port),
            "attempts": self.attempts,
            "attempt_states": self.attempt_states.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "timing_ms": timing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Phases, Source};
    use std::time::Duration;

    fn record() -> ProbeRecord {
        ProbeRecord {
            probe_index: 90412,
            target: "10.20.30.40".into(),
            resolved_address: Some("10.20.30.40".parse().unwrap()),
            port: 443,
            outcome: ProbeOutcome {
                state: State::Open,
                source: Source::ProxyReply,
                reason: None,
                phases: Phases {
                    proxy_connect: Some(Duration::from_micros(1800)),
                    handshake: Some(Duration::from_micros(12400)),
                    connect: Some(Duration::from_micros(21400)),
                    total: Duration::from_micros(35600),
                },
                pressure: None,
            },
            attempts: 2,
            attempt_states: vec![State::Filtered, State::Open],
        }
    }

    #[test]
    fn serializes_all_required_fields() {
        let v = record().to_json();
        assert_eq!(v["target"], "10.20.30.40");
        assert_eq!(v["port"], 443);
        assert_eq!(v["protocol"], "tcp");
        assert_eq!(v["state"], "open");
        assert_eq!(v["source"], "proxy_reply");
        assert_eq!(v["service_label"], "https");
        assert_eq!(v["probe_index"], 90412);
    }

    #[test]
    fn merged_retries_retain_per_attempt_detail() {
        // One row per host:port, but the forensic detail survives (D10).
        let v = record().to_json();
        assert_eq!(v["attempts"], 2);
        assert_eq!(v["attempt_states"][0], "filtered");
        assert_eq!(v["attempt_states"][1], "open");
    }

    #[test]
    fn phases_are_recorded_separately() {
        // Through a proxy a single latency figure is misleading.
        let v = record().to_json();
        assert_eq!(v["timing_ms"]["proxy_connect"], 1.8);
        assert_eq!(v["timing_ms"]["handshake"], 12.4);
        assert_eq!(v["timing_ms"]["connect"], 21.4);
        assert_eq!(v["timing_ms"]["total"], 35.6);
    }

    #[test]
    fn direct_probes_omit_proxy_phases() {
        let mut r = record();
        r.outcome.phases.proxy_connect = None;
        r.outcome.phases.handshake = None;
        let v = r.to_json();
        assert!(v["timing_ms"].get("proxy_connect").is_none());
        assert!(v["timing_ms"].get("handshake").is_none());
        assert!(v["timing_ms"]["connect"].is_number());
    }

    #[test]
    fn unresolved_hostname_records_null_address() {
        let mut r = record();
        r.target = "app.internal".into();
        r.resolved_address = None;
        let v = r.to_json();
        assert!(v["resolved_address"].is_null());
        assert_eq!(v["target"], "app.internal");
    }

    #[test]
    fn unknown_ports_have_no_service_label() {
        let mut r = record();
        r.port = 64321;
        assert!(r.to_json()["service_label"].is_null());
    }
}
