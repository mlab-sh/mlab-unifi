//! Site resolution.
//!
//! Every local endpoint is scoped to a site id, but nobody remembers a UUID.
//! A profile may therefore hold an id, a name, or nothing at all, and this
//! turns whichever it is into the id the API wants.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::ui;
use crate::unifi::{Client, Surface};

/// Turn a site name, or an empty setting, into a site id.
pub async fn resolve(c: &Client, want: &str) -> Result<String> {
    if looks_like_id(want) {
        return Ok(want.to_string());
    }

    let sites = ui::spin("Resolving the site", c.list("/sites", &[], 0, None))
        .await
        .context("listing sites")?;
    let names = |k: &str| {
        sites
            .iter()
            .map(|s| field(s, k))
            .collect::<Vec<_>>()
            .join(", ")
    };

    if want.is_empty() {
        return match sites.len() {
            0 => bail!("this console reports no site"),
            1 => Ok(field(&sites[0], "id")),
            _ => bail!(
                "several sites exist, pick one with --site (or `mlab-unifi login`): {}",
                names("name")
            ),
        };
    }

    for s in &sites {
        if field(s, "id") == want || field(s, "name").eq_ignore_ascii_case(want) {
            return Ok(field(s, "id"));
        }
    }
    bail!("no site named {want:?} (known: {})", names("name"))
}

/// The short site name the internal surfaces use, from the documented UUID.
///
/// The two surfaces disagree on what a site is called: the documented one takes
/// a UUID, the legacy and v2 ones take a short name (`default`). The mapping
/// lives in the legacy site list, under `external_id`.
pub async fn resolve_legacy(c: &Client, site_id: &str) -> Result<String> {
    let sites = ui::spin(
        "Resolving the site",
        c.list_on(Surface::Legacy, "/self/sites", &[]),
    )
    .await
    .context("listing sites on the legacy surface")?;

    for s in &sites {
        if field(s, "external_id") == site_id {
            return Ok(field(s, "name"));
        }
    }
    match sites.len() {
        0 => bail!("the legacy surface reports no site"),
        1 => Ok(field(&sites[0], "name")),
        _ => bail!("no legacy site maps to {site_id}"),
    }
}

fn field(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// A UniFi site id is a UUID; anything else is treated as a name to look up.
fn looks_like_id(s: &str) -> bool {
    s.len() == 36
        && s.matches('-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_uuid_skips_the_lookup() {
        assert!(looks_like_id("88f7af54-98f8-306a-a1c7-c9349722b1f6"));
        assert!(!looks_like_id("Default"));
        assert!(
            !looks_like_id(""),
            "an empty setting means: go and find out"
        );
        assert!(
            !looks_like_id("zzzzzzzz-98f8-306a-a1c7-c9349722b1f6"),
            "not hex"
        );
    }
}
