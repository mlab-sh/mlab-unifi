//! Config storage for the `mlab-unifi` CLI.
//!
//! One file, `$HOME/.mlab/unify.conf` (JSON), holding any number of named
//! profiles plus the name of the default one. Written 0600 inside a 0700 dir:
//! it contains API keys.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Which API a profile talks to.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A console on the LAN: `https://<host>/proxy/network/integration/v1`.
    #[default]
    Local,
    /// The account-wide Site Manager API: `https://api.ui.com`.
    Cloud,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Local => "local",
            Mode::Cloud => "cloud",
        })
    }
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" | "lan" | "console" => Ok(Mode::Local),
            "cloud" | "site-manager" | "sitemanager" | "ui" => Ok(Mode::Cloud),
            other => bail!("unknown mode {other:?} (expected \"local\" or \"cloud\")"),
        }
    }
}

/// Connection parameters for one UniFi console (or the cloud account).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    #[serde(default)]
    pub mode: Mode,
    /// Hostname or `host:port` of the console. Unused in cloud mode.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// API key from the console UI: Settings -> Control Plane -> Integrations.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    /// Default site id for local commands.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub site: String,
    /// Tri-state: `None` means "use the mode default" (see [`Profile::insecure`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// `json` or `table`; `None` means the global default (`json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Profile {
    /// Effective TLS behaviour. Local consoles ship a self-signed certificate,
    /// so certificate verification is skipped there by default; the cloud
    /// endpoint has a real certificate and is always verified.
    pub fn insecure(&self) -> bool {
        match self.mode {
            Mode::Local => self.insecure.unwrap_or(true),
            Mode::Cloud => false,
        }
    }

    /// Reject a profile that cannot produce a request.
    pub fn validate(&self) -> Result<()> {
        if self.api_key.is_empty() {
            bail!("api key is missing (set --api-key, UNIFI_API_KEY, or run `mlab-unifi login`)");
        }
        if self.mode == Mode::Local {
            if self.host.is_empty() {
                bail!("host is missing (set --host, UNIFI_HOST, or run `mlab-unifi login`)");
            }
            normalize_host(&self.host)?;
        }
        Ok(())
    }

    /// A copy with the api key blanked, for printing.
    pub fn redacted(&self) -> Profile {
        let mut p = self.clone();
        p.api_key = redact(&self.api_key);
        p
    }
}

/// Mask an API key down to its last 4 characters.
pub fn redact(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("****{tail}")
}

/// Canonicalize a console host: strip any scheme and trailing slashes, reject a
/// value carrying a path, query, fragment, or whitespace.
pub fn normalize_host(h: &str) -> Result<String> {
    let mut s = h.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        bail!("host is empty");
    }
    if s.contains(['/', '?', '#', ' ', '\t', '\r', '\n']) {
        bail!("host {h:?} must be a hostname or host:port, without a path");
    }
    Ok(s.to_string())
}

/// The whole config file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigFile {
    /// Name of the profile used when `--profile` is not given.
    #[serde(rename = "default", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ConfigFile {
    /// Resolve `name` (or the default profile when `None`).
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        let wanted = match name {
            Some(n) => n.to_string(),
            None => match &self.default_profile {
                Some(d) => d.clone(),
                None if self.profiles.len() == 1 => self.profiles.keys().next().unwrap().clone(),
                _ => bail!("no profile selected and no default set; run `mlab-unifi login`"),
            },
        };
        match self.profiles.get(&wanted) {
            Some(p) => Ok((wanted, p.clone())),
            None => bail!(
                "profile {wanted:?} not found in {} (known: {})",
                path().display(),
                if self.profiles.is_empty() {
                    "none".to_string()
                } else {
                    self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                }
            ),
        }
    }
}

/// `$MLAB_UNIFI_CONFIG`, else `$HOME/.mlab/unify.conf`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_UNIFI_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("unify.conf")
}

/// Read the config file. A missing file is an empty config, not an error.
pub fn load() -> Result<ConfigFile> {
    let p = path();
    let data = match fs::read_to_string(&p) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigFile::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    if data.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    serde_json::from_str(&data).with_context(|| format!("parsing {}", p.display()))
}

/// Write the config file atomically-ish, 0600 in a 0700 directory.
pub fn save(cfg: &ConfigFile) -> Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let mut data = serde_json::to_string_pretty(cfg)?;
    data.push('\n');
    fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
    set_mode(&p, 0o600)?;
    Ok(())
}

/// Non-empty when the config file is readable or writable by group/others.
pub fn perms_warning() -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = path();
        let meta = fs::metadata(&p).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "config {} has mode {mode:04o}; it holds API keys, 0600 is recommended",
                p.display()
            ));
        }
    }
    None
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// First non-empty of `MLAB_UNIFI_<name>` then `UNIFI_<name>`.
pub fn env(name: &str) -> Option<String> {
    for key in [format!("MLAB_UNIFI_{name}"), format!("UNIFI_{name}")] {
        if let Ok(v) = std::env::var(&key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Same as [`env`] but for a boolean, so an explicit `false` can override a file.
pub fn env_bool(name: &str) -> Option<bool> {
    env(name).map(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_strips_scheme_and_slashes() {
        assert_eq!(normalize_host("https://10.0.0.1/").unwrap(), "10.0.0.1");
        assert_eq!(
            normalize_host(" unifi.lan:8443 ").unwrap(),
            "unifi.lan:8443"
        );
        assert!(normalize_host("10.0.0.1/proxy").is_err());
        assert!(normalize_host("  ").is_err());
    }

    #[test]
    fn tls_defaults_per_mode() {
        let local = Profile {
            mode: Mode::Local,
            ..Default::default()
        };
        assert!(
            local.insecure(),
            "local consoles are self-signed, skip verification"
        );

        let strict = Profile {
            insecure: Some(false),
            ..local.clone()
        };
        assert!(!strict.insecure());

        let cloud = Profile {
            mode: Mode::Cloud,
            insecure: Some(true),
            ..Default::default()
        };
        assert!(!cloud.insecure(), "the cloud endpoint is always verified");
    }

    #[test]
    fn validate_requires_key_and_host() {
        let mut p = Profile::default();
        assert!(p.validate().is_err());
        p.api_key = "k".into();
        assert!(p.validate().is_err(), "local mode still needs a host");
        p.host = "10.0.0.1".into();
        assert!(p.validate().is_ok());

        let cloud = Profile {
            mode: Mode::Cloud,
            api_key: "k".into(),
            ..Default::default()
        };
        assert!(cloud.validate().is_ok(), "cloud has a fixed base URL");
    }

    #[test]
    fn redact_keeps_only_the_tail() {
        assert_eq!(redact("abcdefgh"), "****efgh");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn mode_parses_aliases() {
        assert_eq!("LOCAL".parse::<Mode>().unwrap(), Mode::Local);
        assert_eq!("site-manager".parse::<Mode>().unwrap(), Mode::Cloud);
        assert!("nope".parse::<Mode>().is_err());
    }

    #[test]
    fn profile_falls_back_to_the_only_one() {
        let mut cfg = ConfigFile::default();
        cfg.profiles.insert("only".into(), Profile::default());
        assert_eq!(cfg.profile(None).unwrap().0, "only");
        assert!(cfg.profile(Some("other")).is_err());
    }
}
