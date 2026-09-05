//! Published advisories mentioning the hardware on the site, through
//! vuln.mlab.sh.
//!
//! This produces a **reading list, never a verdict**. Two properties of the
//! upstream data make anything stronger dishonest:
//!
//! * NVD catalogues Ubiquiti products at **exact pinned versions**, not
//!   ranges. A CVE says "affects 7.2.95" and nothing about 7.2.94, so an
//!   installed version that does not match tells you nothing.
//! * Several recent entries carry **no product metadata at all**: the model
//!   appears only in the English prose.
//!
//! So matching is on product identity, and an empty result means "no advisory
//! names this model", which is not the same as "this model is unaffected".

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enrich::{cache_dir, now, read_cache, write_cache};
use crate::ui;

const ENDPOINT: &str = "https://vuln.mlab.sh/api/v1/cve";

/// The vendor's advisory list moves slowly; a day is plenty.
const TTL_SECONDS: i64 = 24 * 3600;

/// The corpus holds a few dozen entries for this vendor, so one page covers it.
const PAGE: u32 = 100;

/// Multi-word queries are ANDed upstream and match nothing, so each term is
/// asked for separately and the results merged by id.
const TERMS: [&str; 2] = ["ubiquiti", "unifi"];

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub cvss_severity: Option<String>,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default)]
    pub in_kev: bool,
    #[serde(default)]
    pub affected_products: Vec<String>,
}

impl Advisory {
    /// Everything a model name could appear in, normalized once.
    fn haystack(&self) -> String {
        normalize(&format!(
            "{} {}",
            self.description,
            self.affected_products.join(" ")
        ))
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    #[serde(default)]
    fetched: i64,
    #[serde(default)]
    items: Vec<Advisory>,
}

fn cache_path() -> PathBuf {
    cache_dir().join("advisories-ubiquiti.json")
}

/// What a load attempt produced, so the caller can be precise about it.
#[derive(Default)]
pub struct Outcome {
    pub items: Vec<Advisory>,
    /// True when the list came from the network rather than the cache.
    pub fetched: bool,
    pub error: Option<String>,
}

/// The advisory list, from cache when fresh, from the service otherwise.
pub async fn load(allow_web: bool) -> Outcome {
    let mut out = Outcome::default();

    if let Some(c) = read_cache::<Cache>(&cache_path()) {
        if !c.items.is_empty() && now() - c.fetched < TTL_SECONDS {
            out.items = c.items;
            return out;
        }
    }
    if !allow_web {
        return out;
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("mlab-unifi/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };

    let spinner = ui::Spinner::start("Fetching advisories from vuln.mlab.sh");
    let mut seen = BTreeSet::new();
    let mut items: Vec<Advisory> = Vec::new();

    for term in TERMS {
        match fetch(&http, term).await {
            Ok(page) => {
                for a in page {
                    if seen.insert(a.id.clone()) {
                        items.push(a);
                    }
                }
            }
            Err(e) => {
                out.error = Some(e);
                break;
            }
        }
    }
    spinner.clear();

    if !items.is_empty() {
        out.fetched = true;
        let _ = write_cache(
            &cache_path(),
            &Cache {
                fetched: now(),
                items: items.clone(),
            },
        );
        out.items = items;
    }
    out
}

async fn fetch(http: &reqwest::Client, term: &str) -> Result<Vec<Advisory>, String> {
    let resp = http
        .get(ENDPOINT)
        .query(&[("q", term), ("limit", &PAGE.to_string())])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("vuln.mlab.sh answered {}", resp.status().as_u16()));
    }

    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    let list = body.get("cves").cloned().unwrap_or(Value::Null);
    serde_json::from_value(list).map_err(|e| e.to_string())
}

/// Advisories naming any of `models`.
///
/// Both sides are reduced to lowercase alphanumerics before matching, so
/// `U6-LR` finds `U6-LR`, `u6 lr` and `u6lr` alike. Identifiers shorter than
/// four characters are skipped: they match everything and mean nothing.
pub fn matching<'a>(list: &'a [Advisory], models: &[String]) -> Vec<&'a Advisory> {
    let needles: Vec<String> = models
        .iter()
        .map(|m| normalize(m))
        .filter(|m| m.len() >= 4)
        .collect();
    if needles.is_empty() {
        return Vec::new();
    }

    let mut hits: Vec<&Advisory> = list
        .iter()
        .filter(|a| {
            let hay = a.haystack();
            needles.iter().any(|n| hay.contains(n.as_str()))
        })
        .collect();

    // Actively exploited first, then by severity: the order to read them in.
    hits.sort_by(|a, b| {
        b.in_kev.cmp(&a.in_kev).then(
            b.cvss_score
                .unwrap_or(0.0)
                .total_cmp(&a.cvss_score.unwrap_or(0.0)),
        )
    });
    hits
}

/// Lowercase alphanumerics only: model names are punctuated inconsistently on
/// both sides (`USW-Lite-8-PoE`, `usw lite 8 poe`).
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(id: &str, desc: &str, kev: bool, score: f64) -> Advisory {
        Advisory {
            id: id.into(),
            description: desc.into(),
            in_kev: kev,
            cvss_score: Some(score),
            ..Default::default()
        }
    }

    #[test]
    fn a_model_is_found_however_either_side_punctuates_it() {
        let list = vec![advisory(
            "CVE-2024-54750",
            "Ubiquiti U6-LR 6.6.65 was discovered to contain a hardcoded password",
            false,
            9.8,
        )];
        assert_eq!(matching(&list, &["U6-LR".into()]).len(), 1);
        assert_eq!(matching(&list, &["u6lr".into()]).len(), 1);
        assert_eq!(matching(&list, &["U6 LR".into()]).len(), 1);
    }

    #[test]
    fn a_model_you_do_not_own_does_not_match() {
        let list = vec![advisory(
            "CVE-2023-24104",
            "UniFi Dream Machine Pro v7.2.95",
            false,
            9.8,
        )];
        assert!(matching(&list, &["UDR7".into()]).is_empty());
    }

    #[test]
    fn the_product_metadata_is_searched_as_well_as_the_prose() {
        let mut a = advisory("CVE-1", "an issue", false, 5.0);
        a.affected_products = vec!["Ui Unifi dream machine pro firmware 7.2.95".into()];
        assert_eq!(matching(&[a], &["dream machine pro".into()]).len(), 1);
    }

    #[test]
    fn short_identifiers_are_refused_rather_than_matching_everything() {
        let list = vec![advisory(
            "CVE-1",
            "Ubiquiti UniFi anything at all",
            false,
            5.0,
        )];
        assert!(
            matching(&list, &["ap".into()]).is_empty(),
            "two letters match half the corpus"
        );
        assert!(matching(&list, &[String::new()]).is_empty());
    }

    #[test]
    fn exploited_advisories_are_listed_before_merely_severe_ones() {
        let list = vec![
            advisory("CVE-low", "Ubiquiti UDR7 thing", false, 9.9),
            advisory("CVE-kev", "Ubiquiti UDR7 thing", true, 5.0),
        ];
        let got = matching(&list, &["UDR7".into()]);
        assert_eq!(
            got[0].id, "CVE-kev",
            "known exploitation outranks a higher score"
        );
    }
}
