//! Configuration discovery, loading, and validation.

pub mod builtin;
pub mod error;
pub mod raw;

use std::path::{Path, PathBuf};

pub use error::ConfigError;
use error::suggest;
use raw::{Layer, Layered, LoadedFile, RawConfig, SUPPORTED_VERSION};

use crate::net::{parse_ports, parse_target};
use crate::plan::types::DnsMode;
use crate::units::parse_duration;

pub const USER_CONFIG_RELATIVE: &str = "scanr/config.toml";
pub const PROJECT_CONFIG_NAME: &str = "scanr.toml";

/// Where configuration was found, for `scanr config path`.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub candidates: Vec<(Layer, PathBuf, bool)>,
}

impl Discovery {
    pub fn found(&self) -> impl Iterator<Item = (Layer, &PathBuf)> {
        self.candidates
            .iter()
            .filter(|(_, _, exists)| *exists)
            .map(|(l, p, _)| (*l, p))
    }
}

/// Expand a leading `~` using `$HOME`.
pub fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(p)
}

fn user_config_path() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join(USER_CONFIG_RELATIVE));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join(USER_CONFIG_RELATIVE))
}

/// Search upward from `start` for a project config.
fn project_config_path(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(PROJECT_CONFIG_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Locate configuration files. An explicit path replaces both discovered layers.
pub fn discover(explicit: Option<&Path>, cwd: &Path) -> Discovery {
    if let Some(p) = explicit {
        return Discovery {
            candidates: vec![(Layer::Explicit, p.to_path_buf(), p.is_file())],
        };
    }
    let mut candidates = Vec::new();
    if let Some(u) = user_config_path() {
        let exists = u.is_file();
        candidates.push((Layer::User, u, exists));
    }
    // Report the discovered path if found, otherwise the path we would have used.
    match project_config_path(cwd) {
        Some(p) => candidates.push((Layer::Project, p, true)),
        None => candidates.push((Layer::Project, cwd.join(PROJECT_CONFIG_NAME), false)),
    }
    Discovery { candidates }
}

/// Read and parse every discovered file, lowest precedence first.
pub fn load(discovery: &Discovery) -> Result<Layered, ConfigError> {
    let mut files = Vec::new();
    for (layer, path, exists) in &discovery.candidates {
        if !exists {
            if *layer == Layer::Explicit {
                return Err(ConfigError::new(format!(
                    "config file not found: {}",
                    path.display()
                )));
            }
            continue;
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new(format!("cannot read config: {e}")).at(path.clone()))?;
        let config = parse_config(&text, path)?;
        files.push(LoadedFile {
            layer: *layer,
            path: path.clone(),
            text,
            config,
        });
    }
    files.sort_by_key(|f| f.layer);
    Ok(Layered { files })
}

fn parse_config(text: &str, path: &Path) -> Result<RawConfig, ConfigError> {
    toml::from_str::<RawConfig>(text).map_err(|e| {
        let mut err = ConfigError::new(strip_toml_prefix(&e.to_string())).at(path.to_path_buf());
        if let Some(span) = e.span() {
            err = err.span(span);
        }
        // serde's "unknown field" message lists valid fields; add a typo suggestion.
        if let Some(unknown) = extract_unknown_field(&e.to_string()) {
            // toml's span points at the enclosing table, not the offending key, so
            // relocate the caret when the key can be found.
            if let Some(span) = find_key_span(text, None, &unknown) {
                err = err.span(span);
            }
            // A field valid elsewhere (`fidelity` belongs on a transport, not a scan)
            // would otherwise produce "did you mean `fidelity`?", which reads as a bug.
            if let Some(hint) = suggest(&unknown, known_field_names())
                && hint != unknown
            {
                err = err.help(format!("did you mean `{hint}`?"));
            }
        }
        err
    })
}

/// Pull the human-readable message out of a `toml` error.
///
/// `toml` renders its own caret block, which we duplicate, so it has to be stripped:
///
/// ```text
/// TOML parse error at line 2, column 1
///   |
/// 2 | [scans.s]
///   | ^^^^^^^^^
/// unknown field `fidelity`
/// ```
///
/// The real message is the **last** line, not the first. An earlier version took the
/// first non-structural line and so reported `2 | [scans.s]` as the error text, making
/// every unknown-field error unreadable. `2 | [scans.s]` is not all digits and pipes, so
/// the structural filter let it through.
fn strip_toml_prefix(msg: &str) -> String {
    let is_structural = |t: &str| {
        t.is_empty()
            || t.starts_with("TOML parse error")
            // "  |", "  | ^^^", and "2 | source" are all caret-block furniture.
            || t.starts_with('|')
            || t.split_once('|')
                .is_some_and(|(before, _)| !before.trim().is_empty()
                    && before.trim().chars().all(|c| c.is_ascii_digit()))
    };
    msg.lines()
        .map(str::trim)
        .rfind(|l| !is_structural(l))
        .map(str::to_string)
        .unwrap_or_else(|| msg.lines().next().unwrap_or(msg).trim().to_string())
}

fn extract_unknown_field(msg: &str) -> Option<String> {
    let rest = msg.split("unknown field `").nth(1)?;
    rest.split('`').next().map(|s| s.to_string())
}

fn known_field_names() -> Vec<&'static str> {
    vec![
        "version",
        "defaults",
        "profiles",
        "transports",
        "targets",
        "ports",
        "scans",
        "profile",
        "transport",
        "output_dir",
        "open_only",
        "concurrency",
        "rate",
        "proxy_connect_timeout",
        "handshake_timeout",
        "connect_timeout",
        "retries",
        "retry_delay",
        "type",
        "address",
        "username",
        "password_env",
        "password_file",
        "dns",
        "include",
        "exclude",
        "file",
        "description",
    ]
}

/// Best-effort locator for a `key` inside `[table]`, so semantic errors can render a
/// caret too. Display only — a miss just means no caret.
fn find_key_span(text: &str, table: Option<&str>, key: &str) -> Option<std::ops::Range<usize>> {
    let mut offset = 0usize;
    let mut in_table = table.is_none();
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let lead = line.len() - trimmed.len();
        if trimmed.starts_with('[') {
            if let Some(t) = table {
                let header = trimmed
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .unwrap_or("")
                    .trim();
                in_table = header == t;
            }
            // With no table named, search the whole file: a deserialization error knows
            // the key but not which table it was in, and pointing at the key beats
            // pointing at a table header.
        } else if in_table {
            let name = trimmed.split('=').next().map(|s| s.trim()).unwrap_or("");
            if name == key {
                let start = offset + lead;
                return Some(start..start + key.len());
            }
        }
        offset += line.len();
    }
    None
}

fn err_at(
    files: &Layered,
    path: &Path,
    table: Option<&str>,
    key: &str,
    msg: String,
) -> ConfigError {
    let mut e = ConfigError::new(msg).at(path.to_path_buf());
    if let Some(text) = files.source_of(path)
        && let Some(span) = find_key_span(text, table, key)
    {
        e = e.span(span);
    }
    e
}

/// Validate everything we can without touching the network. Returns every problem
/// found rather than stopping at the first, so one pass fixes the whole file.
///
/// Split by config section rather than done inline: the transport rules alone are half
/// of this, and a single function made it hard to see that every section reports all of
/// its problems rather than the first.
pub fn validate(files: &Layered) -> Vec<ConfigError> {
    let mut errors = Vec::new();
    for file in &files.files {
        let (c, p) = (&file.config, file.path.as_path());
        validate_version(files, p, c, &mut errors);
        for (name, prof) in &c.profiles {
            validate_timing(files, p, &format!("profiles.{name}"), prof, &mut errors);
        }
        validate_transports(files, p, c, &mut errors);
        validate_target_sets(files, p, c, &mut errors);
        validate_port_sets(files, p, c, &mut errors);
        validate_scans(files, p, c, &mut errors);
    }
    errors.extend(validate_references(files));
    errors
}

fn validate_version(files: &Layered, p: &Path, c: &RawConfig, errors: &mut Vec<ConfigError>) {
    match c.version {
        Some(v) if v == SUPPORTED_VERSION => {}
        Some(v) => errors.push(
            err_at(
                files,
                p,
                None,
                "version",
                format!("unsupported config version {v} (this build supports {SUPPORTED_VERSION})"),
            )
            .help("a newer scanr may be required to read this file"),
        ),
        None => errors.push(
            err_at(files, p, None, "version", "missing `version` key".into()).help(format!(
                "add `version = {SUPPORTED_VERSION}` at the top of the file"
            )),
        ),
    }
}

fn validate_transports(files: &Layered, p: &Path, c: &RawConfig, errors: &mut Vec<ConfigError>) {
    for (name, t) in &c.transports {
        let table = format!("transports.{name}");
        validate_transport_kind(files, p, &table, name, t, errors);
        validate_transport_credentials(files, p, &table, name, t, errors);
        validate_transport_modes(files, p, &table, name, t, errors);
    }
}

fn validate_transport_kind(
    files: &Layered,
    p: &Path,
    table: &str,
    name: &str,
    t: &raw::RawTransport,
    errors: &mut Vec<ConfigError>,
) {
    let kind = t.kind.as_deref().unwrap_or("");
    match kind {
        "direct" => {
            if t.address.is_some() {
                errors.push(err_at(
                    files,
                    p,
                    Some(table),
                    "address",
                    format!("transport `{name}` is direct but sets `address`"),
                ));
            }
        }
        "socks5" => match &t.address {
            None => errors.push(
                err_at(
                    files,
                    p,
                    Some(table),
                    "type",
                    format!("socks5 transport `{name}` is missing `address`"),
                )
                .help("add `address = \"127.0.0.1:1080\"`"),
            ),
            Some(a) => {
                if a.parse::<std::net::SocketAddr>().is_err() {
                    errors.push(
                        err_at(
                            files,
                            p,
                            Some(table),
                            "address",
                            format!("`{a}` is not a valid host:port"),
                        )
                        .help("use an IP and port, e.g. \"127.0.0.1:1080\""),
                    );
                }
            }
        },
        "socks4" | "socks4a" => errors.push(
            err_at(
                files,
                p,
                Some(table),
                "type",
                format!("transport `{name}` uses `{kind}`, which scanr does not support"),
            )
            .help(
                "SOCKS4/4a define only four reply codes and cannot distinguish a\n\
                 closed port from a filtered one. Use socks5.",
            ),
        ),
        "" => errors.push(
            err_at(
                files,
                p,
                Some(table),
                "type",
                format!("transport `{name}` is missing `type`"),
            )
            .help("use `type = \"direct\"` or `type = \"socks5\"`"),
        ),
        other => {
            let mut e = err_at(
                files,
                p,
                Some(table),
                "type",
                format!("unknown transport type `{other}`"),
            );
            if let Some(s) = suggest(other, ["direct", "socks5"]) {
                e = e.help(format!("did you mean `{s}`?"));
            }
            errors.push(e);
        }
    }
}

fn validate_transport_credentials(
    files: &Layered,
    p: &Path,
    table: &str,
    name: &str,
    t: &raw::RawTransport,
    errors: &mut Vec<ConfigError>,
) {
    // D14: inline credentials are rejected outright, not warned about.
    if t.password.is_some() {
        errors.push(
            err_at(
                files,
                p,
                Some(table),
                "password",
                format!("transport `{name}` sets an inline `password`"),
            )
            .help(
                "scanr never reads inline passwords, because project config is\n\
                 normally committed to version control. Use one of:\n\
                 \x20 password_env  = \"SCANR_LAB_PASSWORD\"\n\
                 \x20 password_file = \"~/.config/scanr/lab.password\"",
            ),
        );
    }
    if t.password_env.is_some() && t.password_file.is_some() {
        errors.push(err_at(
            files,
            p,
            Some(table),
            "password_file",
            format!("transport `{name}` sets both `password_env` and `password_file`"),
        ));
    }
    if let Some(f) = &t.password_file
        && let Err(e) = check_secret_file_permissions(&expand_home(f))
    {
        errors.push(err_at(files, p, Some(table), "password_file", e));
    }
}

/// Declared fidelity and DNS mode, both of which name a value from a fixed set.
fn validate_transport_modes(
    files: &Layered,
    p: &Path,
    table: &str,
    name: &str,
    t: &raw::RawTransport,
    errors: &mut Vec<ConfigError>,
) {
    if let Some(f) = &t.fidelity
        && crate::plan::types::Fidelity::parse(f).is_none()
    {
        errors.push(
            err_at(
                files,
                p,
                Some(table),
                "fidelity",
                format!("unknown fidelity `{f}` for transport `{name}`"),
            )
            .help(format!(
                "expected one of: {}\nrun `scanr transport test {name}` to measure it",
                crate::plan::types::Fidelity::DECLARABLE.join(", ")
            )),
        );
    }
    if let Some(d) = &t.dns
        && DnsMode::parse(d).is_none()
    {
        let mut e = err_at(
            files,
            p,
            Some(table),
            "dns",
            format!("unknown dns mode `{d}`"),
        );
        if let Some(s) = suggest(d, DnsMode::ALL.iter().copied()) {
            e = e.help(format!("did you mean `{s}`?"));
        } else {
            e = e.help(format!("expected one of: {}", DnsMode::ALL.join(", ")));
        }
        errors.push(e);
    }
}

fn validate_target_sets(files: &Layered, p: &Path, c: &RawConfig, errors: &mut Vec<ConfigError>) {
    for (name, ts) in &c.targets {
        let table = format!("targets.{name}");
        if ts.include.is_none() && ts.file.is_none() {
            errors.push(
                err_at(
                    files,
                    p,
                    Some(&table),
                    "include",
                    format!("target set `{name}` has neither `include` nor `file`"),
                )
                .help("add `include = [\"10.0.0.0/24\"]` or `file = \"hosts.txt\"`"),
            );
        }
        for (field, list) in [("include", &ts.include), ("exclude", &ts.exclude)] {
            if let Some(l) = list {
                for spec in l.items() {
                    if let Err(e) = parse_target(&spec) {
                        errors.push(err_at(files, p, Some(&table), field, e.to_string()));
                    }
                }
            }
        }
    }
}

fn validate_port_sets(files: &Layered, p: &Path, c: &RawConfig, errors: &mut Vec<ConfigError>) {
    for (name, ps) in &c.ports {
        let table = format!("ports.{name}");
        match &ps.ports {
            None => errors.push(err_at(
                files,
                p,
                Some(&table),
                "ports",
                format!("port set `{name}` has no `ports`"),
            )),
            Some(l) => {
                for spec in l.items() {
                    if let Err(e) = parse_ports(&spec) {
                        errors.push(err_at(files, p, Some(&table), "ports", e.to_string()));
                    }
                }
            }
        }
    }
}

fn validate_scans(files: &Layered, p: &Path, c: &RawConfig, errors: &mut Vec<ConfigError>) {
    for (name, s) in &c.scans {
        let table = format!("scans.{name}");
        validate_timing(files, p, &table, &s.timing, errors);
        if let Some(d) = &s.dns
            && DnsMode::parse(d).is_none()
        {
            errors.push(err_at(
                files,
                p,
                Some(&table),
                "dns",
                format!("unknown dns mode `{d}`"),
            ));
        }
        if s.targets.is_none() {
            errors.push(err_at(
                files,
                p,
                Some(&table),
                "targets",
                format!("scan `{name}` has no `targets`"),
            ));
        }
        if s.ports.is_none() {
            errors.push(err_at(
                files,
                p,
                Some(&table),
                "ports",
                format!("scan `{name}` has no `ports`"),
            ));
        }
    }
}

fn validate_timing(
    files: &Layered,
    path: &Path,
    table: &str,
    t: &raw::RawProfile,
    errors: &mut Vec<ConfigError>,
) {
    if let Some(c) = t.concurrency
        && (c == 0 || c > 65535)
    {
        errors.push(
            err_at(
                files,
                path,
                Some(table),
                "concurrency",
                format!("concurrency {c} is out of range"),
            )
            .help("expected 1-65535; this is also the worker thread count"),
        );
    }
    if let Some(r) = t.retries
        && r > 10
    {
        errors.push(err_at(
            files,
            path,
            Some(table),
            "retries",
            format!("retries {r} is out of range (expected 0-10)"),
        ));
    }
    if let Some(r) = t.rate
        && r > 1_000_000
    {
        errors.push(err_at(
            files,
            path,
            Some(table),
            "rate",
            format!("rate {r} is implausibly high (expected 0-1000000, 0 = unlimited)"),
        ));
    }
    for (field, v) in [
        ("proxy_connect_timeout", &t.proxy_connect_timeout),
        ("handshake_timeout", &t.handshake_timeout),
        ("connect_timeout", &t.connect_timeout),
        ("retry_delay", &t.retry_delay),
    ] {
        if let Some(s) = v
            && let Err(e) = parse_duration(s)
        {
            errors.push(err_at(files, path, Some(table), field, e.to_string()));
        }
    }
}

/// Cross-file reference checks, run after every file has been parsed.
fn validate_references(files: &Layered) -> Vec<ConfigError> {
    let mut errors = Vec::new();
    let profiles = files.profile_names();
    let transports = files.transport_names();
    let target_sets = files.target_set_names();
    let port_sets = files.port_set_names();

    let known_profile =
        |n: &str| profiles.iter().any(|p| p == n) || builtin::builtin_profile(n).is_some();
    let known_transport =
        |n: &str| transports.iter().any(|t| t == n) || n == builtin::DEFAULT_TRANSPORT;

    let all_profiles: Vec<String> = profiles
        .iter()
        .cloned()
        .chain(
            builtin::builtin_profile_names()
                .into_iter()
                .map(String::from),
        )
        .collect();

    for file in &files.files {
        let p = file.path.as_path();

        if let Some(n) = &file.config.defaults.profile
            && !known_profile(n)
        {
            errors.push(reference_error(
                files,
                p,
                Some("defaults"),
                "profile",
                "profile",
                n,
                &all_profiles,
            ));
        }
        if let Some(n) = &file.config.defaults.transport
            && !known_transport(n)
        {
            errors.push(reference_error(
                files,
                p,
                Some("defaults"),
                "transport",
                "transport",
                n,
                &transports,
            ));
        }

        for (name, s) in &file.config.scans {
            let table = format!("scans.{name}");
            if let Some(n) = &s.profile
                && !known_profile(n)
            {
                errors.push(reference_error(
                    files,
                    p,
                    Some(&table),
                    "profile",
                    "profile",
                    n,
                    &all_profiles,
                ));
            }
            if let Some(n) = &s.transport
                && !known_transport(n)
            {
                errors.push(reference_error(
                    files,
                    p,
                    Some(&table),
                    "transport",
                    "transport",
                    n,
                    &transports,
                ));
            }
            // Names that match no defined set are parsed as literal specs, so only
            // flag ones that are neither a known set nor a valid spec.
            if let Some(list) = &s.targets {
                for n in list.items() {
                    if !target_sets.contains(&n) && parse_target(&n).is_err() {
                        errors.push(reference_error(
                            files,
                            p,
                            Some(&table),
                            "targets",
                            "target set",
                            &n,
                            &target_sets,
                        ));
                    }
                }
            }
            if let Some(list) = &s.ports {
                for n in list.items() {
                    if !port_sets.contains(&n) && parse_ports(&n).is_err() {
                        errors.push(reference_error(
                            files,
                            p,
                            Some(&table),
                            "ports",
                            "port set",
                            &n,
                            &port_sets,
                        ));
                    }
                }
            }
        }
    }
    errors
}

fn reference_error(
    files: &Layered,
    path: &Path,
    table: Option<&str>,
    key: &str,
    what: &str,
    name: &str,
    candidates: &[String],
) -> ConfigError {
    let mut e = err_at(files, path, table, key, format!("no such {what}: `{name}`"));
    if let Some(s) = suggest(name, candidates.iter().map(|s| s.as_str())) {
        e = e.help(format!("did you mean `{s}`?"));
    } else if !candidates.is_empty() {
        e = e.help(format!("defined {what}s: {}", candidates.join(", ")));
    }
    e
}

/// A credential file readable by anyone but its owner is a real finding, not a nit.
fn check_secret_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::metadata(path)
        .map_err(|e| format!("cannot read password_file {}: {e}", path.display()))?;
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "password_file {} is mode {:04o}; it must not be readable by group or others\n\
             run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raw::Layer;

    fn layered_from(text: &str) -> Layered {
        let config: RawConfig = toml::from_str(text).expect("test config should parse");
        Layered {
            files: vec![LoadedFile {
                layer: Layer::Project,
                path: PathBuf::from("scanr.toml"),
                text: text.to_string(),
                config,
            }],
        }
    }

    fn messages(text: &str) -> Vec<String> {
        validate(&layered_from(text))
            .iter()
            .map(|e| e.message.clone())
            .collect()
    }

    const MINIMAL: &str = "version = 1\n";

    #[test]
    fn minimal_config_is_valid() {
        assert!(validate(&layered_from(MINIMAL)).is_empty());
    }

    #[test]
    fn missing_version_is_reported() {
        let msgs = messages("[defaults]\nprofile = \"proxy\"\n");
        assert!(
            msgs.iter().any(|m| m.contains("missing `version`")),
            "{msgs:?}"
        );
    }

    #[test]
    fn unsupported_version_is_reported() {
        let msgs = messages("version = 99\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("unsupported config version 99")),
            "{msgs:?}"
        );
    }

    #[test]
    fn rejects_inline_password_with_alternatives() {
        let errs = validate(&layered_from(
            "version = 1\n[transports.t]\ntype = \"socks5\"\naddress = \"127.0.0.1:1080\"\npassword = \"hunter2\"\n",
        ));
        let e = errs
            .iter()
            .find(|e| e.message.contains("inline `password`"))
            .expect("inline password must be rejected");
        let help = e.help.as_deref().unwrap_or("");
        assert!(help.contains("password_env"), "{help}");
        assert!(help.contains("password_file"), "{help}");
    }

    #[test]
    fn rejects_socks4_with_an_explanation() {
        let errs = validate(&layered_from(
            "version = 1\n[transports.t]\ntype = \"socks4\"\naddress = \"127.0.0.1:1080\"\n",
        ));
        let e = errs.iter().find(|e| e.message.contains("socks4")).unwrap();
        assert!(e.help.as_deref().unwrap_or("").contains("four reply codes"));
    }

    #[test]
    fn socks5_requires_a_valid_address() {
        assert!(
            messages("version = 1\n[transports.t]\ntype = \"socks5\"\n")
                .iter()
                .any(|m| m.contains("missing `address`"))
        );
        assert!(
            messages("version = 1\n[transports.t]\ntype = \"socks5\"\naddress = \"nope\"\n")
                .iter()
                .any(|m| m.contains("not a valid host:port"))
        );
    }

    #[test]
    fn suggests_transport_type_typo() {
        let errs = validate(&layered_from(
            "version = 1\n[transports.t]\ntype = \"socks\"\n",
        ));
        assert!(
            errs.iter()
                .any(|e| e.help.as_deref() == Some("did you mean `socks5`?"))
        );
    }

    #[test]
    fn validates_timing_ranges() {
        let msgs = messages("version = 1\n[profiles.p]\nconcurrency = 0\nretries = 99\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("concurrency 0 is out of range")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("retries 99")), "{msgs:?}");
    }

    #[test]
    fn validates_durations() {
        let msgs = messages("version = 1\n[profiles.p]\nconnect_timeout = \"5\"\n");
        assert!(msgs.iter().any(|m| m.contains("missing unit")), "{msgs:?}");
    }

    #[test]
    fn detects_undefined_references() {
        let msgs = messages(
            "version = 1\n[scans.s]\nprofile = \"nope\"\ntransport = \"gone\"\ntargets = [\"x\"]\nports = [\"y\"]\n",
        );
        assert!(
            msgs.iter().any(|m| m.contains("no such profile: `nope`")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("no such transport: `gone`")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("no such port set: `y`")),
            "{msgs:?}"
        );
    }

    #[test]
    fn literal_specs_are_accepted_where_a_set_name_would_go() {
        // `targets = ["10.0.0.0/24"]` should work without defining a named set.
        let msgs =
            messages("version = 1\n[scans.s]\ntargets = [\"10.0.0.0/24\"]\nports = [\"80,443\"]\n");
        assert!(msgs.is_empty(), "{msgs:?}");
    }

    #[test]
    fn builtin_profiles_resolve_without_definition() {
        let msgs = messages(
            "version = 1\n[scans.s]\nprofile = \"proxy\"\ntargets = [\"10.0.0.1\"]\nports = [\"80\"]\n",
        );
        assert!(msgs.is_empty(), "{msgs:?}");
    }

    #[test]
    fn target_set_needs_include_or_file() {
        let msgs = messages("version = 1\n[targets.t]\nexclude = [\"10.0.0.1\"]\n");
        assert!(
            msgs.iter()
                .any(|m| m.contains("neither `include` nor `file`")),
            "{msgs:?}"
        );
    }

    #[test]
    fn invalid_target_specs_are_reported() {
        let msgs = messages("version = 1\n[targets.t]\ninclude = [\"10.0.0.0/33\"]\n");
        assert!(msgs.iter().any(|m| m.contains("prefix")), "{msgs:?}");
    }

    #[test]
    fn dns_mode_is_validated_with_suggestion() {
        let errs = validate(&layered_from(
            "version = 1\n[transports.t]\ntype = \"direct\"\ndns = \"locl\"\n",
        ));
        let e = errs
            .iter()
            .find(|e| e.message.contains("dns mode"))
            .unwrap();
        assert_eq!(e.help.as_deref(), Some("did you mean `local`?"));
    }

    #[test]
    fn finds_key_spans_within_the_right_table() {
        let text = "[a]\nkey = 1\n\n[b]\nkey = 2\n";
        let a = find_key_span(text, Some("a"), "key").unwrap();
        let b = find_key_span(text, Some("b"), "key").unwrap();
        assert_eq!(&text[a.clone()], "key");
        assert!(b.start > a.start, "should find b's key, not a's");
        assert_eq!(text[..b.start].matches('\n').count(), 4);
    }

    #[test]
    fn key_span_absent_for_missing_table() {
        assert!(find_key_span("[a]\nkey = 1\n", Some("zzz"), "key").is_none());
    }

    #[test]
    fn toml_message_is_the_real_error_not_the_source_line() {
        // toml puts its message *after* the caret block it renders. Taking the first
        // non-structural line reported `2 | [scans.s]` as the error text, which made
        // every unknown-field error unreadable.
        let raw = "TOML parse error at line 2, column 1\n  |\n2 | [scans.s]\n  | ^^^^^^^^^\nunknown field `fidelity`\n";
        assert_eq!(strip_toml_prefix(raw), "unknown field `fidelity`");

        let raw2 =
            "TOML parse error at line 3, column 5\n  |\n3 | rate = \n  |     ^\ninvalid string\n";
        assert_eq!(strip_toml_prefix(raw2), "invalid string");
    }

    #[test]
    fn key_span_search_spans_all_tables_when_none_is_named() {
        // A deserialization error knows the key but not its table, so the caret should
        // still find the key rather than fall back to the table header.
        let text = "version = 1\n[scans.s]\ntargets = []\nfidelity = \"full\"\n";
        let span = find_key_span(text, None, "fidelity").expect("should find the key");
        assert_eq!(&text[span.clone()], "fidelity");
        assert_eq!(
            text[..span.start].matches('\n').count(),
            3,
            "should be line 4"
        );
    }

    #[test]
    fn unknown_field_is_extracted_for_suggestions() {
        let msg = "unknown field `concurrancy`, expected one of `concurrency`, `rate`";
        assert_eq!(extract_unknown_field(msg).as_deref(), Some("concurrancy"));
    }

    #[test]
    fn errors_accumulate_rather_than_stopping_at_the_first() {
        let msgs = messages(
            "version = 99\n[profiles.p]\nconcurrency = 0\n[transports.t]\ntype = \"bogus\"\n",
        );
        assert!(msgs.len() >= 3, "expected several errors, got {msgs:?}");
    }
}
