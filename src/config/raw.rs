//! Deserialized TOML shapes, plus the layered lookup that gives every resolved value
//! a provenance.
//!
//! Rather than merging the user and project files into one structure and losing track
//! of where values came from, we keep the layers and resolve by walking them from
//! highest precedence down. The first hit wins and reports its own origin — which is
//! what makes `scanr plan` able to answer "why is concurrency 512?".

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const SUPPORTED_VERSION: u32 = 1;

/// Where a resolved value came from. Rendered in `scanr plan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Compiled-in fallback.
    Default,
    /// A built-in profile's value.
    BuiltinProfile(String),
    /// `[defaults]` in a config file.
    Defaults(PathBuf),
    /// `[profiles.<name>]` in a config file.
    Profile(String, PathBuf),
    /// `[transports.<name>]` in a config file.
    Transport(String, PathBuf),
    /// `[scans.<name>]` in a config file.
    Scan(String, PathBuf),
    /// An environment variable (credentials only).
    Env(String),
    /// A command-line override.
    Cli,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Default => write!(f, "builtin"),
            Origin::BuiltinProfile(p) => write!(f, "builtin.{p}"),
            Origin::Defaults(_) => write!(f, "defaults"),
            Origin::Profile(n, _) => write!(f, "profile.{n}"),
            Origin::Transport(n, _) => write!(f, "transport.{n}"),
            Origin::Scan(n, _) => write!(f, "scan.{n}"),
            Origin::Env(v) => write!(f, "env:{v}"),
            Origin::Cli => write!(f, "cli"),
        }
    }
}

impl Origin {
    pub fn file(&self) -> Option<&Path> {
        match self {
            Origin::Defaults(p)
            | Origin::Profile(_, p)
            | Origin::Transport(_, p)
            | Origin::Scan(_, p) => Some(p),
            _ => None,
        }
    }
}

/// Which discovered file a layer came from. Project wins over user (D13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    User,
    Project,
    /// Supplied via `--config`, which replaces both.
    Explicit,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Layer::User => write!(f, "user"),
            Layer::Project => write!(f, "project"),
            Layer::Explicit => write!(f, "explicit"),
        }
    }
}

/// Accepts either `ports = "80,443"` or `ports = ["80", "443"]`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    pub fn items(&self) -> Vec<String> {
        match self {
            StringOrVec::One(s) => vec![s.clone()],
            StringOrVec::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub version: Option<u32>,
    #[serde(default)]
    pub defaults: RawDefaults,
    #[serde(default)]
    pub profiles: BTreeMap<String, RawProfile>,
    #[serde(default)]
    pub transports: BTreeMap<String, RawTransport>,
    #[serde(default)]
    pub targets: BTreeMap<String, RawTargetSet>,
    #[serde(default)]
    pub ports: BTreeMap<String, RawPortSet>,
    #[serde(default)]
    pub scans: BTreeMap<String, RawScan>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    pub profile: Option<String>,
    pub transport: Option<String>,
    pub output_dir: Option<String>,
    pub open_only: Option<bool>,
    pub compress: Option<bool>,
    pub spans: Option<bool>,
    /// Read what open services volunteer on connect. On by default; `--no-banner` turns
    /// it off. Nothing is ever sent — only services that greet first say anything — so it
    /// adds no traffic to the target beyond the connection the scan already made.
    pub banner: Option<bool>,
    /// A file of `name port/proto` lines to label ports from, ahead of `/etc/services`
    /// and the builtin table. `~` is expanded.
    pub services_file: Option<String>,
    /// Read `/etc/services` for port labels. Default true. Set false for labels that
    /// depend only on this config and the binary, and so match on every machine.
    pub use_etc_services: Option<bool>,
}

/// Timing knobs. Also inlineable on a scan, which is why this is its own type.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawProfile {
    pub concurrency: Option<u32>,
    pub rate: Option<u32>,
    pub proxy_connect_timeout: Option<String>,
    pub handshake_timeout: Option<String>,
    pub connect_timeout: Option<String>,
    pub retries: Option<u32>,
    pub retry_delay: Option<String>,
    /// Cap on bytes read from an open service when banner grabbing is on.
    pub banner_bytes: Option<u32>,
    /// How long to wait for a service to volunteer a greeting.
    pub banner_timeout: Option<String>,
}

impl RawProfile {
    pub fn is_empty(&self) -> bool {
        *self == RawProfile::default()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTransport {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub address: Option<String>,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub password_file: Option<String>,
    /// Present only so we can reject it with a useful message (D14). Never read.
    pub password: Option<toml::Value>,
    pub dns: Option<String>,
    /// Result fidelity, as measured by `scanr transport test` and recorded here by the
    /// operator. Declaring it is what turns the "not measured" warning off, and it
    /// keeps the fact in version control rather than in a hidden cache (D8).
    pub fidelity: Option<String>,
    /// `type = "chain"`: SOCKS5 transports traversed in order, each reached through the
    /// one before it.
    pub hops: Option<StringOrVec>,
    /// `type = "pool"`: transports probed across rather than through.
    pub members: Option<StringOrVec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTargetSet {
    pub include: Option<StringOrVec>,
    pub exclude: Option<StringOrVec>,
    /// Line-delimited file of targets; `#` comments and blank lines are skipped.
    pub file: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPortSet {
    pub ports: Option<StringOrVec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawScan {
    pub description: Option<String>,
    pub profile: Option<String>,
    pub transport: Option<String>,
    pub targets: Option<StringOrVec>,
    pub ports: Option<StringOrVec>,
    pub exclude: Option<StringOrVec>,
    pub open_only: Option<bool>,
    pub compress: Option<bool>,
    pub spans: Option<bool>,
    pub banner: Option<bool>,
    pub dns: Option<String>,
    pub output_dir: Option<String>,
    /// Inline timing overrides, same shape as a profile.
    #[serde(flatten)]
    pub timing: RawProfile,
}

/// One config file as loaded, retaining its text so errors can render carets.
#[derive(Debug, Clone)]
pub struct LoadedFile {
    pub layer: Layer,
    pub path: PathBuf,
    pub text: String,
    pub config: RawConfig,
}

/// The discovered config files, ordered lowest precedence first.
#[derive(Debug, Clone, Default)]
pub struct Layered {
    pub files: Vec<LoadedFile>,
}

impl Layered {
    /// Walk layers highest-precedence-first, returning the first hit and its file.
    pub fn pick<T>(&self, mut f: impl FnMut(&RawConfig) -> Option<T>) -> Option<(T, PathBuf)> {
        for file in self.files.iter().rev() {
            if let Some(v) = f(&file.config) {
                return Some((v, file.path.clone()));
            }
        }
        None
    }

    /// Union of a named table's keys across all layers.
    pub fn names<'a>(
        &'a self,
        mut f: impl FnMut(&'a RawConfig) -> Vec<&'a String> + 'a,
    ) -> Vec<String> {
        let mut out: Vec<String> = self
            .files
            .iter()
            .flat_map(|file| f(&file.config))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn profile_names(&self) -> Vec<String> {
        self.names(|c| c.profiles.keys().collect())
    }

    pub fn transport_names(&self) -> Vec<String> {
        self.names(|c| c.transports.keys().collect())
    }

    pub fn target_set_names(&self) -> Vec<String> {
        self.names(|c| c.targets.keys().collect())
    }

    pub fn port_set_names(&self) -> Vec<String> {
        self.names(|c| c.ports.keys().collect())
    }

    pub fn scan_names(&self) -> Vec<String> {
        self.names(|c| c.scans.keys().collect())
    }

    pub fn source_of(&self, path: &Path) -> Option<&str> {
        self.files
            .iter()
            .find(|f| f.path == path)
            .map(|f| f.text.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> RawConfig {
        toml::from_str(s).expect("valid config")
    }

    fn layered(user: &str, project: &str) -> Layered {
        Layered {
            files: vec![
                LoadedFile {
                    layer: Layer::User,
                    path: PathBuf::from("/home/u/.config/scanr/config.toml"),
                    text: user.into(),
                    config: parse(user),
                },
                LoadedFile {
                    layer: Layer::Project,
                    path: PathBuf::from("./scanr.toml"),
                    text: project.into(),
                    config: parse(project),
                },
            ],
        }
    }

    #[test]
    fn accepts_string_or_vec_ports() {
        let a = parse("[ports.web]\nports = \"80,443\"");
        let b = parse("[ports.web]\nports = [\"80\", \"443\"]");
        assert_eq!(a.ports["web"].ports.as_ref().unwrap().items(), ["80,443"]);
        assert_eq!(
            b.ports["web"].ports.as_ref().unwrap().items(),
            ["80", "443"]
        );
    }

    #[test]
    fn scan_accepts_inline_timing_overrides() {
        let c = parse(
            r#"
            [scans.s]
            profile = "proxy"
            connect_timeout = "8s"
            concurrency = 64
        "#,
        );
        let s = &c.scans["s"];
        assert_eq!(s.profile.as_deref(), Some("proxy"));
        assert_eq!(s.timing.connect_timeout.as_deref(), Some("8s"));
        assert_eq!(s.timing.concurrency, Some(64));
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = toml::from_str::<RawConfig>("[profiles.p]\nconcurrancy = 5").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn rejects_unknown_top_level_table() {
        assert!(toml::from_str::<RawConfig>("[nonsense]\nx = 1").is_err());
    }

    #[test]
    fn project_layer_wins_per_key() {
        let l = layered(
            "[profiles.p]\nconcurrency = 100\nrate = 50\n",
            "[profiles.p]\nconcurrency = 200\n",
        );
        // Overridden key comes from project...
        let (c, path) = l
            .pick(|c| c.profiles.get("p").and_then(|p| p.concurrency))
            .unwrap();
        assert_eq!(c, 200);
        assert_eq!(path, PathBuf::from("./scanr.toml"));

        // ...while the untouched key still resolves from the user layer.
        let (r, path) = l
            .pick(|c| c.profiles.get("p").and_then(|p| p.rate))
            .unwrap();
        assert_eq!(r, 50);
        assert!(path.ends_with("config.toml"));
    }

    #[test]
    fn names_are_unioned_across_layers() {
        let l = layered(
            "[profiles.a]\n[profiles.b]\n",
            "[profiles.b]\n[profiles.c]\n",
        );
        assert_eq!(l.profile_names(), ["a", "b", "c"]);
    }

    #[test]
    fn pick_returns_none_when_absent() {
        let l = layered("", "");
        assert!(l.pick(|c| c.defaults.profile.clone()).is_none());
    }

    #[test]
    fn origin_renders_compactly() {
        assert_eq!(Origin::Default.to_string(), "builtin");
        assert_eq!(
            Origin::BuiltinProfile("proxy".into()).to_string(),
            "builtin.proxy"
        );
        assert_eq!(
            Origin::Profile("proxy".into(), "/x".into()).to_string(),
            "profile.proxy"
        );
        assert_eq!(
            Origin::Scan("internal-web".into(), "/x".into()).to_string(),
            "scan.internal-web"
        );
        assert_eq!(Origin::Cli.to_string(), "cli");
        assert_eq!(Origin::Env("SCANR_PW".into()).to_string(), "env:SCANR_PW");
    }

    #[test]
    fn password_field_is_captured_for_rejection() {
        // D14: we parse it only so validation can produce a useful error.
        let c = parse("[transports.t]\ntype = \"socks5\"\npassword = \"hunter2\"");
        assert!(c.transports["t"].password.is_some());
    }
}
