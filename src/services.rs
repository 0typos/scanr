//! Service labels — what usually lives on a port number.
//!
//! Three layers, most specific first:
//!
//!   1. a file named by `defaults.services_file`, if the config sets one
//!   2. `/etc/services`, if it exists
//!   3. the compiled-in table below
//!
//! A lookup takes the first layer that has an answer, so a two-line custom file still
//! gets everything else for free.
//!
//! None of this is a fingerprint. Nothing connects to the service or reads a banner —
//! the port answered, and a table says what usually sits on that number. Port 4444 is
//! `krb524` to every one of these layers and is essentially never Kerberos.
//!
//! ## On reproducibility
//!
//! Reading the host's `/etc/services` means the same scan can label the same port
//! differently on two machines, which the old compiled-in-only table could not do. That
//! is the cost of better labels and it is accepted deliberately (D31). It is paid for by
//! provenance: every record says which layers produced its labels and how many entries
//! each contributed, so a difference between two records is explainable rather than
//! mysterious. `state`, `source` and `reason` — the fields anything automated should key
//! on — are untouched by any of this.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A *file* source of labels, identified for the record.
///
/// The builtin is not a variant: only file layers are recorded in `stats`, and giving it
/// one meant a state the type allowed and the code could never produce. It appears in
/// `provenance()` as a literal, always last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// The host's `/etc/services`.
    Etc(PathBuf),
    /// A file named by `defaults.services_file`.
    Configured(PathBuf),
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Layer::Etc(p) | Layer::Configured(p)) = self;
        write!(f, "{}", p.display())
    }
}

/// A file that could not be read. Only ever raised for a *configured* file: naming a
/// path that is not there is a mistake worth stopping for, whereas `/etc/services` is
/// optional by construction and its absence is simply the next layer's turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFileError {
    pub path: PathBuf,
    pub detail: String,
}

impl std::fmt::Display for ServiceFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot read {}: {}", self.path.display(), self.detail)
    }
}

/// Lines a file layer contributed, and lines it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerStats {
    pub layer: Layer,
    pub entries: usize,
    pub malformed: usize,
}

/// The resolved label table for one scan.
#[derive(Debug, Clone)]
pub struct ServiceTable {
    /// Only what the file layers supplied. The builtin is a function, not a map, so it
    /// costs nothing to carry and cannot be shadowed by accident.
    learned: HashMap<u16, Box<str>>,
    stats: Vec<LayerStats>,
    /// `/etc/services` was declined by config rather than missing.
    ///
    /// Both end with the layer absent from `stats`, but they are different situations:
    /// one is a container without the file, the other is a deliberate trade of label
    /// coverage for labels that match on every machine. Someone comparing two records
    /// needs to be able to tell which.
    etc_suppressed: bool,
}

pub const ETC_SERVICES: &str = "/etc/services";

impl ServiceTable {
    /// The compiled-in table alone. What every lookup falls back to, and what the
    /// process uses if nothing installs anything else.
    pub fn builtin_only() -> Self {
        Self {
            learned: HashMap::new(),
            stats: Vec::new(),
            etc_suppressed: false,
        }
    }

    /// Build the layered table: the configured file, then `/etc/services`, then the
    /// builtin.
    ///
    /// `etc` is a parameter rather than a constant so tests can exercise the real
    /// precedence rules against a fixture instead of against whatever the machine
    /// running them happens to have in `/etc`.
    pub fn resolve(
        configured: Option<&Path>,
        etc: Option<&Path>,
    ) -> Result<Self, ServiceFileError> {
        let mut t = Self::builtin_only();

        // Highest priority first: `or_insert` means the first layer to claim a port
        // keeps it, which is also what makes the first name on a line canonical.
        if let Some(path) = configured {
            let text = std::fs::read_to_string(path).map_err(|e| ServiceFileError {
                path: path.to_path_buf(),
                detail: e.to_string(),
            })?;
            t.absorb(Layer::Configured(path.to_path_buf()), &text);
        }

        if let Some(path) = etc {
            // Missing or unreadable is not an error: "when it exists" is the whole
            // contract, and a container image without one is normal.
            if let Ok(text) = std::fs::read_to_string(path) {
                t.absorb(Layer::Etc(path.to_path_buf()), &text);
            }
        }

        Ok(t)
    }

    /// The layered table for ordinary use, reading the real `/etc/services` unless the
    /// config has opted out.
    ///
    /// Opting out is how a caller buys back the reproducibility that reading the host's
    /// file costs (D31): with `use_etc` false the labels depend only on the config and
    /// the binary, so two machines agree by construction.
    pub fn resolve_from_host(
        configured: Option<&Path>,
        use_etc: bool,
    ) -> Result<Self, ServiceFileError> {
        let etc = Path::new(ETC_SERVICES);
        let mut t = Self::resolve(configured, (use_etc && etc.exists()).then_some(etc))?;
        t.etc_suppressed = !use_etc;
        Ok(t)
    }

    /// Whether `/etc/services` was declined rather than simply absent.
    pub fn etc_suppressed(&self) -> bool {
        self.etc_suppressed
    }

    /// Parse one `/etc/services`-format file into the table.
    ///
    /// The format is `name port/proto [aliases...]`, `#` to end of line a comment. It is
    /// also close enough to `nmap-services` that pointing at one works — the extra
    /// frequency column parses as an alias and is ignored.
    fn absorb(&mut self, layer: Layer, text: &str) {
        let mut entries = 0;
        let mut malformed = 0;

        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(name), Some(addr)) = (fields.next(), fields.next()) else {
                // A lone token is a truncated entry, not a comment.
                malformed += 1;
                continue;
            };
            let Some((port, proto)) = addr.split_once('/') else {
                malformed += 1;
                continue;
            };
            // UDP and SCTP rows are well-formed and simply not ours; this is a TCP
            // connect scanner. Counting them as malformed would report `/etc/services`
            // as roughly half broken on every machine.
            if !proto.eq_ignore_ascii_case("tcp") {
                continue;
            }
            match port.parse::<u16>() {
                Ok(0) | Err(_) => {
                    malformed += 1;
                    continue;
                }
                // First layer to claim a port keeps it, which is also what makes the
                // first name on a line the canonical one. `entry` rather than
                // `contains_key` + `insert` so the key is hashed once.
                Ok(p) => {
                    if let std::collections::hash_map::Entry::Vacant(v) = self.learned.entry(p) {
                        v.insert(name.into());
                        entries += 1;
                    }
                }
            }
        }

        self.stats.push(LayerStats {
            layer,
            entries,
            malformed,
        });
    }

    /// The label for a port, or `None` if no layer knows it.
    pub fn lookup(&self, port: u16) -> Option<&str> {
        match self.learned.get(&port) {
            Some(name) => Some(name),
            None => builtin(port),
        }
    }

    /// Layers that contributed, most specific first.
    pub fn layers(&self) -> &[LayerStats] {
        &self.stats
    }

    /// Files that parsed but gave up lines, for the plan's warnings.
    pub fn malformed(&self) -> impl Iterator<Item = &LayerStats> {
        self.stats.iter().filter(|s| s.malformed > 0)
    }

    /// Ports the builtin is still the answer for — those no file layer claimed.
    ///
    /// Reported instead of the flat table size so `entries` means the same thing on
    /// every row: what that layer contributed. A stock Linux `/etc/services` names 57 of
    /// the builtin's 59 ports, so the flat figure double-counted almost all of them and
    /// the rows did not sum to the size of the table they described.
    ///
    /// Note this counts ports *claimed*, not ports *relabelled* — `/etc/services` agrees
    /// with the builtin about `ssh` on 22, and 22 still belongs to the layer that got
    /// there first.
    ///
    /// A full sweep of the port space, once per scan, against a `HashMap` that is at
    /// most a few thousand entries.
    fn builtin_contribution(&self) -> usize {
        (0..=u16::MAX)
            .filter(|p| builtin(*p).is_some() && !self.learned.contains_key(p))
            .count()
    }

    /// One line naming the layers in effect, for `plan`.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .stats
            .iter()
            .map(|s| {
                let name = match &s.layer {
                    // Spelled in full: "services (5862)" for /etc/services reads like
                    // some file called `services`.
                    Layer::Etc(p) => p.display().to_string(),
                    // A configured path can be arbitrarily long, and the row it goes in
                    // is one line; the record carries the full path.
                    Layer::Configured(p) => p
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.display().to_string()),
                };
                format!("{name} ({})", crate::units::commas(s.entries as u64))
            })
            .collect();
        parts.push(format!(
            "builtin ({})",
            crate::units::commas(self.builtin_contribution() as u64)
        ));
        let mut s = parts.join(" + ");
        if self.etc_suppressed {
            s.push_str(" [/etc/services off]");
        }
        s
    }

    /// What goes in the record's `config` event, so a reader can explain why two scans
    /// of the same port disagree.
    pub fn provenance(&self) -> serde_json::Value {
        let mut layers: Vec<serde_json::Value> = self
            .stats
            .iter()
            .map(|s| {
                serde_json::json!({
                    "source": s.layer.to_string(),
                    "entries": s.entries,
                    "malformed": s.malformed,
                })
            })
            .collect();
        // Always last, always present: every table ends here.
        layers.push(serde_json::json!({
            "source": "builtin",
            "entries": self.builtin_contribution(),
            "malformed": 0,
        }));
        serde_json::json!({
            "layers": layers,
            // False means declined; a host that simply has no /etc/services still reads
            // true here, and the layer's absence says the rest.
            "use_etc_services": !self.etc_suppressed,
        })
    }
}

/// The compiled-in layer: ~55 well-known ports, present on every machine.
///
/// Deliberately small. It is the floor, not an attempt to reproduce IANA — anything
/// wanting breadth should point at `/etc/services` or a file of its own.
fn builtin(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "ms-sql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        3000 => "http-alt",
        3128 => "squid",
        3306 => "mysql",
        3389 => "ms-wbt",
        4444 => "krb524",
        5000 => "upnp",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kube-apiserver",
        7001 => "weblogic",
        8000 | 8001 => "http-alt",
        8080 | 8081 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "http-alt",
        9092 => "kafka",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        27017 | 27018 => "mongodb",
        _ => return None,
    })
}

/// Ports in the compiled-in table. Asserted against the table itself in the tests, so it
/// cannot drift.
///
/// Not what the record reports for the builtin layer — that is `builtin_contribution()`,
/// which excludes ports a file layer already claimed.
pub const BUILTIN_PORTS: usize = 59;

// ── the process-wide table ──────────────────────────────────────────────────

/// Set once, at startup, from the resolved config.
///
/// A global rather than a threaded parameter because the alternative is passing a table
/// through `ProbeRecord::to_json` and every one of its callers, to reach a field that is
/// advisory. It is write-once and read-only afterwards, so there is no shared mutable
/// state and no lock on the hot path.
static INSTALLED: OnceLock<ServiceTable> = OnceLock::new();

/// Install the table for the rest of the process. The first call wins; later ones are
/// ignored, which keeps a second call in a test from changing another test's labels.
pub fn install(table: ServiceTable) {
    let _ = INSTALLED.set(table);
}

/// The active table, defaulting to the builtin if nothing was installed — so a library
/// caller, or a command that never loads a config, still gets labels.
pub fn active() -> &'static ServiceTable {
    INSTALLED.get_or_init(ServiceTable::builtin_only)
}

/// The label for a port under the active table.
///
/// Still returns `&'static str` because `active()` is `&'static`, which is why adding
/// three layers underneath it changed no call site.
pub fn service_label(port: u16) -> Option<&'static str> {
    active().lookup(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture file in its own temporary directory.
    ///
    /// The returned `TempDir` must be held for the life of the test; dropping it removes
    /// the file. That is the point: the hand-rolled version this replaced built a path
    /// from the pid and relied on a trailing `remove_file` in each test, which never ran
    /// when an assertion failed — leaving fixtures behind for the next run to collide
    /// with, under names that had to be kept unique by hand.
    fn tmp(name: &str, body: impl AsRef<[u8]>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, body).expect("write fixture");
        (dir, path)
    }

    const ETC: &str = "\
# /etc/services fragment
ssh             22/tcp
domain          53/tcp          nameserver
domain          53/udp          nameserver
http            80/tcp          www www-http
gopher          70/tcp
http-alt        8080/tcp        webcache
";

    #[test]
    fn builtin_port_count_matches_the_table() {
        let n = (0..=u16::MAX).filter(|p| builtin(*p).is_some()).count();
        assert_eq!(
            n, BUILTIN_PORTS,
            "BUILTIN_PORTS is written into every record's provenance; keep it exact"
        );
    }

    #[test]
    fn the_builtin_alone_answers_when_nothing_else_is_configured() {
        let t = ServiceTable::builtin_only();
        assert_eq!(t.lookup(22), Some("ssh"));
        assert_eq!(t.lookup(5432), Some("postgresql"));
        assert_eq!(t.lookup(64321), None);
        assert!(t.layers().is_empty(), "no file layers to report");
    }

    #[test]
    fn a_services_file_supplies_ports_the_builtin_lacks() {
        let (_etc_dir, etc) = tmp("gopher", ETC);
        let t = ServiceTable::resolve(None, Some(&etc)).expect("fixture is readable");
        // 70 is in no builtin arm.
        assert_eq!(t.lookup(70), Some("gopher"));
        // ...and the builtin still answers underneath it.
        assert_eq!(t.lookup(5432), Some("postgresql"));
    }

    #[test]
    fn etc_services_outranks_the_builtin() {
        let (_etc_dir, etc) = tmp("outranks", ETC);
        let t = ServiceTable::resolve(None, Some(&etc)).expect("fixture is readable");
        // The builtin calls 8080 http-proxy; this file calls it http-alt. The file wins,
        // which is the whole point of reading it.
        assert_eq!(builtin(8080), Some("http-proxy"));
        assert_eq!(t.lookup(8080), Some("http-alt"));
    }

    #[test]
    fn a_configured_file_outranks_etc_services() {
        let (_etc_dir, etc) = tmp("prec-etc", ETC);
        let (_mine_dir, mine) = tmp(
            "prec-mine",
            "internal-api   8080/tcp\nbuild-cache    9099/tcp\n",
        );
        let t = ServiceTable::resolve(Some(&mine), Some(&etc)).expect("fixtures are readable");

        assert_eq!(t.lookup(8080), Some("internal-api"), "configured file wins");
        assert_eq!(t.lookup(70), Some("gopher"), "etc still fills its own gaps");
        assert_eq!(t.lookup(9099), Some("build-cache"), "and the custom file's");
        assert_eq!(
            t.lookup(5432),
            Some("postgresql"),
            "builtin underneath both"
        );

        // Most specific first, so the record reads top-down.
        let layers: Vec<String> = t.layers().iter().map(|l| l.layer.to_string()).collect();
        assert_eq!(
            layers,
            vec![mine.display().to_string(), etc.display().to_string()]
        );
    }

    #[test]
    fn udp_rows_are_skipped_without_being_called_broken() {
        // Roughly half of a real /etc/services is udp. Counting those as malformed would
        // make every scan warn about the system's own file.
        let (_etc_dir, etc) = tmp("udp", ETC);
        let t = ServiceTable::resolve(None, Some(&etc)).expect("fixture is readable");
        assert_eq!(t.layers()[0].malformed, 0, "udp is not a parse failure");
        assert_eq!(t.lookup(53), Some("domain"));
    }

    #[test]
    fn the_first_name_for_a_port_is_the_canonical_one() {
        // Aliases follow the canonical name on the line, and duplicate lines for one
        // port list the preferred spelling first.
        let (_f_dir, f) = tmp("first-wins", "www 80/tcp\nhttp 80/tcp\n");
        let t = ServiceTable::resolve(Some(&f), None).expect("fixture is readable");
        assert_eq!(t.lookup(80), Some("www"));
        assert_eq!(t.layers()[0].entries, 1, "the second line adds nothing");
    }

    #[test]
    fn comments_and_blank_lines_are_not_entries() {
        let (_f_dir, f) = tmp(
            "comments",
            "\n# a comment\n\nssh 22/tcp   # trailing\n   \n",
        );
        let t = ServiceTable::resolve(Some(&f), None).expect("fixture is readable");
        assert_eq!(t.layers()[0].entries, 1);
        assert_eq!(t.layers()[0].malformed, 0);
    }

    #[test]
    fn unparseable_lines_are_counted_not_fatal() {
        let (_f_dir, f) = tmp(
            "malformed",
            "ssh 22/tcp\nlonely\nnoslash 80\nbadport 99999/tcp\nzero 0/tcp\n",
        );
        let t = ServiceTable::resolve(Some(&f), None).expect("a partly broken file still loads");
        assert_eq!(t.lookup(22), Some("ssh"), "the good line still counts");
        let stat = &t.layers()[0];
        assert_eq!(stat.entries, 1);
        assert_eq!(stat.malformed, 4, "lonely, noslash, 99999, and 0");
        assert_eq!(t.malformed().count(), 1, "one layer to warn about");
    }

    #[test]
    fn an_nmap_services_file_parses() {
        // Same first two columns, plus a frequency. Worth supporting: it is the obvious
        // file to reach for, and it has far more ports than /etc/services.
        let (_f_dir, f) = tmp("nmap", "http 80/tcp 0.484143\nkerberos-sec 88/udp 0.001\n");
        let t = ServiceTable::resolve(Some(&f), None).expect("fixture is readable");
        assert_eq!(t.lookup(80), Some("http"));
        assert_eq!(
            t.layers()[0].malformed,
            0,
            "the frequency column is just an alias"
        );
    }

    #[test]
    fn a_configured_file_that_is_not_there_is_an_error() {
        let missing = PathBuf::from("/nonexistent/scanr/services");
        let err = ServiceTable::resolve(Some(&missing), None)
            .expect_err("naming a path that is not there is a mistake, not a fallback");
        assert_eq!(err.path, missing);
        assert!(err.to_string().contains("cannot read"), "{err}");
    }

    #[test]
    fn a_missing_etc_services_is_not_an_error() {
        // Containers routinely lack it. "When it exists" is the contract.
        let t = ServiceTable::resolve(None, Some(Path::new("/nonexistent/etc/services")))
            .expect("absence is the next layer's turn");
        assert_eq!(t.lookup(22), Some("ssh"), "builtin still answers");
        assert!(
            t.layers().is_empty(),
            "a layer that contributed nothing is not listed"
        );
    }

    #[test]
    fn provenance_always_ends_at_the_builtin() {
        let t = ServiceTable::builtin_only();
        let p = t.provenance();
        let layers = p["layers"].as_array().expect("layers array");
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0]["source"], "builtin");
        assert_eq!(layers[0]["entries"], BUILTIN_PORTS);
    }

    #[test]
    fn provenance_names_every_layer_in_priority_order() {
        let (_etc_dir, etc) = tmp("prov-etc", ETC);
        let (_mine_dir, mine) = tmp("prov-mine", "internal-api 8080/tcp\nlonely\n");
        let t = ServiceTable::resolve(Some(&mine), Some(&etc)).expect("fixtures are readable");

        let p = t.provenance();
        let layers = p["layers"].as_array().expect("layers array");
        assert_eq!(layers.len(), 3, "configured, etc, builtin");
        assert_eq!(layers[0]["source"], mine.display().to_string());
        assert_eq!(layers[0]["malformed"], 1);
        assert_eq!(layers[1]["source"], etc.display().to_string());
        assert_eq!(layers[2]["source"], "builtin");
    }

    #[test]
    fn summary_reads_left_to_right_by_priority() {
        let (_etc_dir, etc) = tmp("sum-etc", ETC);
        let t = ServiceTable::resolve(None, Some(&etc)).expect("fixture is readable");
        let s = t.summary();
        assert!(s.contains(" + "), "{s}");
        // The fixture claims 22, 53, 80 and 8080, all of which the builtin also has, so
        // the builtin is left answering for four fewer ports than it holds. Reporting
        // its flat size here double-counted them.
        assert!(
            s.ends_with(&format!("builtin ({})", BUILTIN_PORTS - 4)),
            "{s}"
        );
    }

    /// The documented meaning of `entries` is "what this layer contributed", so the rows
    /// have to account for exactly the ports the table can answer for. The builtin row
    /// reported its full size regardless of shadowing, which broke this: a stock
    /// `/etc/services` claims 57 of its 59.
    #[test]
    fn layer_entries_account_for_every_port_exactly_once() {
        let (_etc_dir, etc) = tmp("sum-inv-etc", ETC);
        let (_mine_dir, mine) = tmp(
            "sum-inv-mine",
            "internal-api 8080/tcp\nbuild-cache 9099/tcp\n",
        );
        let t = ServiceTable::resolve(Some(&mine), Some(&etc)).expect("fixtures are readable");

        let reported: u64 = t.provenance()["layers"]
            .as_array()
            .expect("layers array")
            .iter()
            .map(|l| l["entries"].as_u64().expect("entries"))
            .sum();
        let answerable = (0..=u16::MAX).filter(|p| t.lookup(*p).is_some()).count() as u64;
        assert_eq!(
            reported, answerable,
            "the layer rows must sum to the ports the table answers for"
        );
    }

    #[test]
    fn the_real_etc_services_parses_cleanly_where_it_exists() {
        // The fixtures above are ones I wrote, so they prove the parser matches my idea
        // of the format. This one checks the idea against the machine's actual file.
        let path = Path::new(ETC_SERVICES);
        if !path.exists() {
            return;
        }
        let t = ServiceTable::resolve(None, Some(path)).expect("existing file must read");
        let stat = &t.layers()[0];
        assert!(
            stat.entries > 100,
            "only {} tcp entries — parser too strict",
            stat.entries
        );
        assert!(
            stat.malformed * 20 < stat.entries,
            "{} malformed against {} good: the format assumption is wrong",
            stat.malformed,
            stat.entries
        );
        assert_eq!(t.lookup(22), Some("ssh"), "every /etc/services has this");
    }

    #[test]
    fn pathological_lines_are_survivable() {
        // The parser reads a file the user chose but did not necessarily write — an
        // /etc/services from a distro, an nmap-services from the internet. It should
        // account for junk, not fall over on it.
        let (_f_dir, f) = tmp(
            "pathological",
            "\u{0}/tcp\n///\n80/tcp\nname 80/tcp/extra\n \t \n\
             x -1/tcp\nx 65536/tcp\nx 22/TCP\nx 22/tcp\u{7f}\n#\n\u{1f600} 81/tcp\n",
        );
        let t = ServiceTable::resolve(Some(&f), None).expect("readable");
        // Case-insensitive proto, so this one counts.
        assert_eq!(t.lookup(22), Some("x"));
        assert_eq!(
            t.lookup(81),
            Some("\u{1f600}"),
            "non-ASCII names are just names"
        );
        // And the port that follows a bad line is unaffected by it.
        assert!(t.layers()[0].malformed > 0);
    }

    #[test]
    fn a_non_utf8_configured_file_is_rejected_not_ignored() {
        let (_dir, p) = tmp("binary", [0xff, 0xfe, 0x00, 0x01]);
        let err = ServiceTable::resolve(Some(&p), None)
            .expect_err("a file that is not text was not the file they meant");
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn declining_etc_services_leaves_the_configured_file_and_the_builtin() {
        let (_mine_dir, mine) = tmp("decline", "internal-api 8080/tcp\n");
        let t = ServiceTable::resolve_from_host(Some(&mine), false).expect("fixture is readable");

        assert_eq!(
            t.lookup(8080),
            Some("internal-api"),
            "the custom file still applies"
        );
        assert_eq!(t.lookup(22), Some("ssh"), "and the builtin underneath it");
        // 70 is in /etc/services on this machine and in neither other layer.
        assert_eq!(t.lookup(70), None, "the host file was not consulted");

        assert_eq!(t.layers().len(), 1, "only the configured layer contributed");
        assert!(t.etc_suppressed());
        assert_eq!(t.provenance()["use_etc_services"], false);
        assert!(
            t.summary().contains("[/etc/services off]"),
            "{}",
            t.summary()
        );
    }

    #[test]
    fn declining_is_distinguishable_from_the_file_being_absent() {
        // Both leave the layer out of `stats`; only the flag separates them, and a
        // record with no /etc/services layer is ambiguous without it.
        let absent = ServiceTable::resolve(None, Some(Path::new("/nonexistent/etc/services")))
            .expect("absence is fine");
        assert!(
            !absent.etc_suppressed(),
            "missing is not the same as declined"
        );
        assert_eq!(absent.provenance()["use_etc_services"], true);
        assert!(!absent.summary().contains("off"), "{}", absent.summary());

        let declined = ServiceTable::resolve_from_host(None, false).expect("no file to read");
        assert!(declined.etc_suppressed());
        assert_eq!(declined.layers().len(), 0);
        // Same empty layer list, different explanation.
        assert_ne!(
            absent.provenance()["use_etc_services"],
            declined.provenance()["use_etc_services"]
        );
    }

    #[test]
    fn declining_makes_labels_independent_of_the_host() {
        // The reproducibility that reading /etc/services costs, bought back: this is the
        // same table on any machine, which is the entire reason the knob exists.
        let t = ServiceTable::resolve_from_host(None, false).expect("no file to read");
        assert_eq!(
            t.lookup(8080),
            Some("http-proxy"),
            "the builtin's answer, everywhere"
        );
        assert_eq!(t.lookup(70), None);
    }

    #[test]
    fn the_installed_table_defaults_to_the_builtin() {
        // Nothing installs one in the library tests, so this exercises the fallback that
        // keeps `service_label` working for a caller that never loads a config.
        assert_eq!(service_label(443), Some("https"));
        assert_eq!(service_label(64321), None);
    }
}
