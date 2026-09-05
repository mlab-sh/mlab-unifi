//! Vendor from an OUI, through mlab.sh.
//!
//! The last resort, used only for addresses nothing local could name. Two rules
//! keep it cheap and quiet:
//!
//! * **Only the OUI is sent**, with the device bytes zeroed
//!   (`88:a2:9e:00:00:00`). The answer is identical, since a vendor lookup only
//!   reads the first three bytes, and no device identifier leaves the network.
//! * **The cache is keyed by OUI**, not by device. An OUI assignment does not
//!   change, so one lookup answers for every device sharing that prefix, now
//!   and later.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enrich::{cache_dir, now, read_cache, write_cache};
use crate::ui;

const ENDPOINT: &str = "https://mlab.sh/api/v1/scan/mac";

/// OUI registrations do not move, so the cache can be long lived.
const TTL_SECONDS: i64 = 90 * 24 * 3600;

/// Enough requests to fill the gaps on a normal site, few enough that a
/// misconfigured run cannot hammer the service.
const MAX_LOOKUPS: usize = 64;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub vendor: Option<String>,
    /// Set when the prefix belongs to a hypervisor: VMware, Docker, Xen.
    /// The console never reports this, and a virtual machine on the network is
    /// worth knowing about.
    pub virtualization: Option<String>,
    pub verdict: String,
    fetched: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Cache {
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
}

fn cache_path() -> PathBuf {
    cache_dir().join("oui.json")
}

impl Cache {
    pub fn load() -> Cache {
        read_cache(&cache_path()).unwrap_or_default()
    }

    fn fresh(&self, oui: &str) -> Option<&Entry> {
        self.entries
            .get(oui)
            .filter(|e| now() - e.fetched < TTL_SECONDS)
    }

    fn save(&self) {
        // A cache we cannot write costs a few requests next time, nothing more.
        let _ = write_cache(&cache_path(), self);
    }
}

/// What a resolution run did, so the caller can tell the user.
#[derive(Default, Debug)]
pub struct Outcome {
    pub found: HashMap<String, Entry>,
    /// OUIs actually sent to mlab.sh, as opposed to served from the cache.
    pub queried: usize,
    /// Set when the service could not be reached; the run continues without it.
    pub error: Option<String>,
}

/// Resolve `ouis`, from the cache first and from mlab.sh for the rest.
///
/// With `allow_web` false nothing leaves the machine: the cache still answers
/// for prefixes seen before, which is usually most of them.
pub async fn resolve(ouis: &BTreeSet<String>, allow_web: bool) -> Outcome {
    let mut cache = Cache::load();
    let mut out = Outcome::default();

    let mut missing: Vec<&String> = Vec::new();
    for oui in ouis {
        match cache.fresh(oui) {
            Some(e) => {
                out.found.insert(oui.clone(), e.clone());
            }
            None => missing.push(oui),
        }
    }

    if missing.is_empty() || !allow_web {
        return out;
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("mlab-unifi/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };

    let count = missing.len().min(MAX_LOOKUPS);
    let label = format!("Resolving {count} vendor(s) through mlab.sh");
    let spinner = ui::Spinner::start(&label);

    for oui in missing.into_iter().take(MAX_LOOKUPS) {
        match fetch(&http, oui).await {
            Ok(entry) => {
                out.queried += 1;
                cache.entries.insert(oui.clone(), entry.clone());
                out.found.insert(oui.clone(), entry);
            }
            Err(e) => {
                // One reachable failure is enough to know the rest will fail
                // too; do not sit through a timeout per prefix.
                out.error = Some(e);
                break;
            }
        }
    }

    spinner.clear();
    cache.save();
    out
}

/// One lookup, sending the prefix only.
async fn fetch(http: &reqwest::Client, oui: &str) -> Result<Entry, String> {
    let mac = format!("{}:{}:{}:00:00:00", &oui[0..2], &oui[2..4], &oui[4..6]);

    let resp = http
        .get(ENDPOINT)
        .query(&[("mac", mac.as_str())])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("mlab.sh answered {}", resp.status().as_u16()));
    }

    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);

    Ok(Entry {
        vendor: text("vendor"),
        virtualization: text("virtualization"),
        verdict: text("verdict").unwrap_or_default(),
        fetched: now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_entry_is_not_served() {
        let mut cache = Cache::default();
        cache.entries.insert(
            "88a29e".into(),
            Entry {
                vendor: Some("Raspberry Pi (Trading) Ltd".into()),
                virtualization: None,
                verdict: "Vendor assigned".into(),
                fetched: now() - TTL_SECONDS - 1,
            },
        );
        assert!(cache.fresh("88a29e").is_none());

        cache.entries.get_mut("88a29e").unwrap().fetched = now();
        assert!(cache.fresh("88a29e").is_some());
    }

    #[tokio::test]
    async fn nothing_leaves_the_machine_without_the_flag() {
        let want: BTreeSet<String> = ["000000".to_string()].into_iter().collect();
        let out = resolve(&want, false).await;
        assert_eq!(out.queried, 0);
        assert!(out.error.is_none(), "declining to ask is not an error");
    }
}
