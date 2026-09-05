//! Turning what the console observed into an identity.
//!
//! Two independent sources, both cached on disk so a repeated run costs
//! nothing:
//!
//! * [`fingerprint`] resolves the console's own numeric fingerprint ids
//!   (device model, vendor, operating system, family) against the lookup table
//!   the console itself serves. Entirely local.
//! * [`oui`] resolves a vendor from the first three bytes of a MAC, through
//!   mlab.sh, and only for the addresses nothing local could name.

pub mod fingerprint;
pub mod oui;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Where both caches live: `$HOME/.mlab/unifi/`.
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("unifi")
}

/// Read a cache file, or `None` when it is absent or unreadable. A corrupt
/// cache is never fatal: the caller refetches.
fn read_cache<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Option<T> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Write a cache file, creating `$HOME/.mlab/unifi/` at 0700 if needed.
fn write_cache<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700);
    }
    let data = serde_json::to_string(value)?;
    fs::write(path, data).with_context(|| format!("writing {}", path.display()))?;
    set_mode(path, 0o600);
    Ok(())
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Seconds since the Unix epoch, for cache expiry.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The first three bytes of a MAC, lowercase and stripped: the OUI, and the
/// cache key for a vendor lookup.
pub fn oui_of(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    Some(hex[..6].to_ascii_lowercase())
}

/// Whether a MAC is locally administered, which means it was randomized rather
/// than assigned. Bit 1 of the first octet.
///
/// This is the one case where "unknown vendor" is an answer rather than a gap:
/// there is no registration behind the address, so no table can ever name it,
/// and querying one would leak a device identifier for nothing.
pub fn is_randomized(mac: &str) -> bool {
    oui_of(mac)
        .and_then(|o| u8::from_str_radix(&o[..2], 16).ok())
        .map(|b| b & 0b10 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oui_is_the_first_three_bytes_however_the_mac_is_written() {
        assert_eq!(oui_of("88:A2:9E:5F:36:85").as_deref(), Some("88a29e"));
        assert_eq!(oui_of("88-a2-9e-5f-36-85").as_deref(), Some("88a29e"));
        assert_eq!(oui_of("88a2.9e5f.3685").as_deref(), Some("88a29e"));
        assert_eq!(oui_of("zz"), None);
    }

    #[test]
    fn the_locally_administered_bit_marks_a_randomized_address() {
        // Observed on the lab console: these clients hide their identity.
        assert!(is_randomized("c2:34:34:6a:7c:31"));
        assert!(is_randomized("da:e8:b0:d3:bb:88"));
        assert!(is_randomized("56:6f:4b:41:7d:2c"));
        // Registered prefixes: Raspberry Pi, Ubiquiti, VMware.
        assert!(!is_randomized("88:a2:9e:5f:36:85"));
        assert!(!is_randomized("a8:9c:6c:20:16:e6"));
        assert!(!is_randomized("00:0c:29:11:22:33"));
    }
}
