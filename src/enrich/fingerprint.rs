//! The console's own device fingerprint database.
//!
//! The console watches DHCP, HTTP and mDNS and stores what it concluded as
//! numeric ids on each client: `dev_id`, `dev_vendor`, `os_name`, `dev_family`.
//! Unreadable on their own, and the lookup table that decodes them is served by
//! the same console, so the join is local and can never be out of step with the
//! ids it resolves.
//!
//! The table is around 850 KB and carries no cache headers, so it is cached
//! here under `$HOME/.mlab/unifi/` with a TTL of our own.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enrich::{cache_dir, now, read_cache, write_cache};
use crate::ui;
use crate::unifi::{Client, Surface};

/// How long a cached table is trusted. The console updates it with firmware,
/// so a week is generous without going stale in a way that matters.
const TTL_SECONDS: i64 = 7 * 24 * 3600;

/// The decoded lookup tables, plus when they were fetched.
#[derive(Serialize, Deserialize, Default)]
pub struct Table {
    #[serde(default)]
    fetched: i64,
    #[serde(default)]
    dev_ids: HashMap<String, DevEntry>,
    #[serde(default)]
    vendor_ids: HashMap<String, String>,
    #[serde(default)]
    family_ids: HashMap<String, String>,
    #[serde(default)]
    os_name_ids: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct DevEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    vendor_id: String,
    #[serde(default)]
    family_id: String,
    #[serde(default)]
    os_name_id: String,
}

impl Table {
    pub fn is_empty(&self) -> bool {
        self.dev_ids.is_empty() && self.vendor_ids.is_empty()
    }
}

/// What we could work out about one client.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Identity {
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub device: Option<String>,
    pub family: Option<String>,
    /// The console's own confidence, 0 to 100, when it reported one.
    pub confidence: Option<u8>,
}

impl Identity {
    /// Nothing local could name this device.
    pub fn is_unknown(&self) -> bool {
        self.vendor.is_none() && self.os.is_none() && self.device.is_none()
    }

    /// Whether a model or an operating system was *inferred* by the console's
    /// fingerprint engine, as opposed to read from a registry.
    ///
    /// The distinction is what the confidence applies to. A vendor derived from
    /// an OUI is a registry lookup: it carries no confidence because it needs
    /// none. Only an inference can be wrong in the probabilistic sense.
    pub fn is_inferred(&self) -> bool {
        self.device.is_some() || self.os.is_some()
    }

    /// An inference the console itself does not stand behind. Below the
    /// threshold the model is a guess, and must not read as a fact.
    pub fn is_uncertain(&self, min_score: u8) -> bool {
        self.is_inferred() && self.confidence.unwrap_or(0) < min_score
    }
}

/// The cache file for one console, keyed by host so two consoles never share.
fn cache_path(host: &str) -> PathBuf {
    let safe: String = host
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    cache_dir().join(format!("fingerprints-{safe}.json"))
}

/// The lookup table, from the cache when it is fresh, from the console
/// otherwise. `refresh` forces a fetch.
pub async fn load(c: &Client, host: &str, refresh: bool) -> Result<Table> {
    let path = cache_path(host);

    if !refresh {
        if let Some(t) = read_cache::<Table>(&path) {
            if !t.is_empty() && now() - t.fetched < TTL_SECONDS {
                return Ok(t);
            }
        }
    }

    let raw = ui::spin(
        "Fetching the fingerprint table",
        c.request_on(
            Surface::V2,
            reqwest::Method::GET,
            // Not scoped to a site: the table is the console's, not the site's.
            "/fingerprint_devices/0",
            &[],
            None,
        ),
    )
    .await?;

    let table = parse(&raw);
    if !table.is_empty() {
        // A cache we cannot write is an annoyance, not a failure.
        let _ = write_cache(&path, &table);
    }
    Ok(table)
}

/// Pull the four tables we use out of the console's response.
fn parse(raw: &Value) -> Table {
    let strings = |key: &str| -> HashMap<String, String> {
        raw.get(key)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    let dev_ids = raw
        .get("dev_ids")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    let get = |f: &str| {
                        v.get(f)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    };
                    (
                        k.clone(),
                        DevEntry {
                            name: get("name"),
                            vendor_id: get("vendor_id"),
                            family_id: get("family_id"),
                            os_name_id: get("os_name_id"),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    Table {
        fetched: now(),
        dev_ids,
        vendor_ids: strings("vendor_ids"),
        family_ids: strings("family_ids"),
        os_name_ids: strings("os_name_ids"),
    }
}

/// Resolve one client record from the legacy surface.
///
/// The per-client ids win over the ones on the matched device signature: the
/// console set them for this device, the signature is the generic model.
pub fn resolve(t: &Table, rec: &Value) -> Identity {
    let id = |k: &str| rec.get(k).and_then(Value::as_i64).map(|n| n.to_string());

    let dev = id("dev_id").and_then(|d| t.dev_ids.get(&d).cloned());
    let pick =
        |direct: Option<String>, from_dev: Option<String>, table: &HashMap<String, String>| {
            direct
                .or(from_dev)
                .filter(|k| !k.is_empty())
                .and_then(|k| table.get(&k).cloned())
                .filter(|s| !s.is_empty())
        };

    Identity {
        vendor: pick(
            id("dev_vendor"),
            dev.as_ref().map(|d| d.vendor_id.clone()),
            &t.vendor_ids,
        ),
        os: pick(
            id("os_name"),
            dev.as_ref().map(|d| d.os_name_id.clone()),
            &t.os_name_ids,
        ),
        family: pick(
            id("dev_family"),
            dev.as_ref().map(|d| d.family_id.clone()),
            &t.family_ids,
        ),
        device: dev.map(|d| d.name).filter(|s| !s.is_empty()),
        confidence: rec
            .get("confidence")
            .and_then(Value::as_i64)
            .map(|n| n.clamp(0, 100) as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table() -> Table {
        parse(&json!({
            "dev_ids": {
                "4841": {"name": "iPhone ", "vendor_id": "320", "family_id": "9", "os_name_id": "24"},
                "38":   {"name": "",        "vendor_id": "17",  "family_id": "7", "os_name_id": "3"}
            },
            "vendor_ids": {"320": "Apple, Inc.", "17": "Raspberry Pi (Trading) Ltd"},
            "family_ids": {"9": "Smartphone", "7": "Network & Peripheral"},
            "os_name_ids": {"24": "Apple iOS", "3": "Linux"}
        }))
    }

    #[test]
    fn a_device_signature_resolves_to_names() {
        let got = resolve(&table(), &json!({"dev_id": 4841, "confidence": 99}));
        assert_eq!(
            got.device.as_deref(),
            Some("iPhone"),
            "trailing spaces are trimmed"
        );
        assert_eq!(got.vendor.as_deref(), Some("Apple, Inc."));
        assert_eq!(got.os.as_deref(), Some("Apple iOS"));
        assert_eq!(got.family.as_deref(), Some("Smartphone"));
        assert_eq!(got.confidence, Some(99));
    }

    #[test]
    fn per_client_ids_win_over_the_signature() {
        // The console tagged this one Raspberry Pi even though the signature it
        // matched is an Apple device.
        let got = resolve(&table(), &json!({"dev_id": 4841, "dev_vendor": 17}));
        assert_eq!(got.vendor.as_deref(), Some("Raspberry Pi (Trading) Ltd"));
        assert_eq!(got.device.as_deref(), Some("iPhone"));
    }

    #[test]
    fn a_client_with_no_fingerprint_resolves_to_nothing() {
        let got = resolve(&table(), &json!({"mac": "88:a2:9e:5f:36:85"}));
        assert!(got.is_unknown());
        assert_eq!(got.confidence, None);
    }

    #[test]
    fn an_empty_signature_name_is_not_an_identity() {
        let got = resolve(&table(), &json!({"dev_id": 38}));
        assert_eq!(got.device, None, "an empty name must not become a model");
        assert_eq!(got.vendor.as_deref(), Some("Raspberry Pi (Trading) Ltd"));
        assert!(!got.is_unknown(), "the vendor still names it");
    }

    #[test]
    fn a_registry_vendor_carries_no_confidence_and_needs_none() {
        // Resolved from the OUI, not inferred: counting it as "below 90%"
        // would drown the real guesses in noise.
        let vendor_only = Identity {
            vendor: Some("Dell Inc.".into()),
            ..Default::default()
        };
        assert!(!vendor_only.is_inferred());
        assert!(!vendor_only.is_uncertain(90));
        assert!(!vendor_only.is_unknown());
    }

    #[test]
    fn confidence_gates_assertion_but_not_knowledge() {
        let sure = resolve(&table(), &json!({"dev_id": 4841, "confidence": 99}));
        let guess = resolve(&table(), &json!({"dev_id": 4841, "confidence": 60}));
        assert!(!sure.is_uncertain(90));
        assert!(guess.is_uncertain(90));
        assert!(
            !guess.is_unknown(),
            "a low score is still an identification"
        );
    }

    #[test]
    fn a_missing_confidence_counts_as_uncertain_not_as_perfect() {
        let got = resolve(&table(), &json!({"dev_id": 4841}));
        assert!(got.is_uncertain(90));
    }
}
