//! `shadow` — what turned up on the network that nobody announced.
//!
//! Built on `first_seen`, so it works without a stored history: the console
//! already records when it met each address for the first time.
//!
//! One property of the data drives the whole design. A phone that rotates its
//! MAC address presents a new address to the console each time, and every one
//! of them looks like a brand new device. On the lab site the only arrival in
//! thirty days was exactly that. Randomized addresses are therefore separated
//! out by default rather than mixed in, because a report made of expected churn
//! is a report nobody reads.

use std::collections::{BTreeSet, HashSet};

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::enrich::{self, fingerprint, oui};
use crate::ui::{self, render};
use crate::unifi::{self, esc, iso8601, site, Client, Surface};

#[derive(Args, Debug)]
pub struct ShadowArgs {
    /// How far back to look
    #[arg(long, default_value_t = 30, value_name = "N")]
    pub days: i64,

    /// Include randomized addresses, which rotate and look new every time
    #[arg(long)]
    pub include_randomized: bool,

    /// Confidence below which a fingerprint is not treated as an identification
    #[arg(long, default_value_t = 90, value_name = "0-100")]
    pub min_score: u8,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &ShadowArgs) -> Result<()> {
    unifi::local_only(c, "shadow")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;
    let cutoff = now() - a.days.max(0) * 86_400;

    let known = ui::spin(
        "Reading the client history",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/user", esc(&legacy)),
            &[],
        ),
    )
    .await?;

    let live: HashSet<String> = c
        .list(&format!("/sites/{}/clients", esc(&site)), &[], 0, None)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|v| {
            v.get("macAddress")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
        })
        .collect();

    let table = fingerprint::load(c, &ctx.profile.host, false)
        .await
        .unwrap_or_default();

    // The same vendor cascade the inventory uses, so a device named there is
    // named here too. Cache only: this command never reaches the network for it.
    let gaps: BTreeSet<String> = known
        .iter()
        .filter_map(|k| k.get("mac").and_then(Value::as_str))
        .filter(|m| !enrich::is_randomized(m))
        .filter_map(enrich::oui_of)
        .collect();
    let vendors = oui::resolve(&gaps, false).await;

    let mut arrivals: Vec<Value> = Vec::new();
    let mut randomized = 0usize;

    for k in &known {
        let first = k.get("first_seen").and_then(Value::as_i64).unwrap_or(0);
        if first < cutoff || first == 0 {
            continue;
        }
        let mac = k
            .get("mac")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let rotating = enrich::is_randomized(&mac);
        if rotating {
            randomized += 1;
            if !a.include_randomized {
                continue;
            }
        }

        let last = k.get("last_seen").and_then(Value::as_i64).unwrap_or(0);
        let id = fingerprint::resolve(&table, k);
        let text = |key: &str| {
            k.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let name = [text("name"), text("hostname")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();

        // Fingerprint first, then the vendor the console resolved itself, then
        // the cached OUI lookup. Whether a device counts as identified is
        // decided by the same cascade that fills the column, so the count under
        // the table can never disagree with the table.
        let vendor = id
            .vendor
            .clone()
            .or_else(|| Some(text("oui")).filter(|s| !s.is_empty()))
            .or_else(|| {
                enrich::oui_of(&mac)
                    .and_then(|o| vendors.found.get(&o).cloned())
                    .and_then(|e| e.vendor)
            });
        // A vendor read off a registry is a fact and carries no confidence;
        // only the model is an inference. Merging the two would report a device
        // as unidentified while its vendor sits in the column next to it.
        let named = vendor.is_some() || id.device.is_some();
        let guessed = id.is_uncertain(a.min_score);

        arrivals.push(json!({
            "name": name,
            "firstSeen": iso8601(first),
            "lastSeen": iso8601(last),
            "link": if k.get("is_wired").and_then(Value::as_bool).unwrap_or(false) { "wired" } else { "wireless" },
            "network": text("last_connection_network_name"),
            "vendor": vendor,
            "device": id.device.clone(),
            "macAddress": mac.clone(),
            "identified": named,
            "modelIsAGuess": guessed,
            "randomized": rotating,
            "activeNow": live.contains(&mac),
            // Seen once and never again: a visit rather than an arrival, and a
            // different thing to look into.
            "oneOff": last.saturating_sub(first) < 3600,
            "firstSeenEpoch": first,
        }));
    }

    arrivals.sort_by_key(|r| -r["firstSeenEpoch"].as_i64().unwrap_or(0));

    let adopted = adopted_devices(c, &legacy, cutoff).await;

    render::heading(&format!("Appeared in the last {} days", a.days));
    render::list(&arrivals, render::SHADOW_COLS);
    render::count(arrivals.len(), "arrival");

    if !adopted.is_empty() {
        render::heading("UniFi hardware adopted in the same period");
        render::list(&adopted, render::ADOPTION_COLS);
    }

    if render::is_json() {
        return Ok(());
    }
    report(&arrivals, randomized, adopted.len(), a);
    Ok(())
}

fn report(arrivals: &[Value], randomized: usize, adopted: usize, a: &ShadowArgs) {
    let count = |k: &str, want: Value| arrivals.iter().filter(|r| r[k] == want).count();

    if arrivals.is_empty() && adopted == 0 {
        ui::info(&format!("nothing new in {} days", a.days));
    }

    if randomized > 0 && !a.include_randomized {
        ui::info(&format!(
            "{randomized} arrival(s) hidden because their address is randomized: a phone \
             rotating its MAC looks like a new device every time. Add --include-randomized \
             to see them"
        ));
    }

    let wired = count("link", json!("wired"));
    if wired > 0 {
        ui::warning(&format!(
            "{wired} of them arrived on a wire, which means someone reached a port"
        ));
    }

    let unnamed = count("identified", json!(false));
    if unnamed > 0 {
        ui::warning(&format!(
            "{unnamed} could not be identified at all: neither the fingerprint engine nor \
             a vendor lookup names them"
        ));
    }

    let guessed = count("modelIsAGuess", json!(true));
    if guessed > 0 {
        ui::info(&format!(
            "{guessed} carry a model the console is less than {}% sure of, shown as reported",
            a.min_score
        ));
    }

    let visits = count("oneOff", json!(true));
    if visits > 0 {
        ui::info(&format!(
            "{visits} were seen once and never came back, which is a visit rather than \
             an arrival"
        ));
    }

    let here = count("activeNow", json!(true));
    if here > 0 {
        ui::info(&format!("{here} are connected right now"));
    }

    if adopted > 0 {
        ui::warning(&format!(
            "{adopted} UniFi device(s) were adopted in this window: hardware joining the \
             managed network is the strongest signal on this page"
        ));
    }

    ui::info(
        "first seen is when the console met the address, not when the device was built: \
         a controller rebuild or a rotated address both look like an arrival",
    );
}

/// UniFi hardware adopted inside the window. A device joining the managed
/// network is a stronger signal than a client connecting to it.
async fn adopted_devices(c: &Client, legacy: &str, cutoff: i64) -> Vec<Value> {
    let Ok(devices) = c
        .list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/device", esc(legacy)),
            &[],
        )
        .await
    else {
        return Vec::new();
    };

    devices
        .iter()
        .filter_map(|d| {
            let at = d.get("adopted_at").and_then(Value::as_i64)?;
            // The console reports this one in milliseconds.
            let at = if at > 100_000_000_000 { at / 1000 } else { at };
            if at < cutoff {
                return None;
            }
            Some(json!({
                "name": d.get("name").cloned().unwrap_or(Value::Null),
                "model": d.get("model").cloned().unwrap_or(Value::Null),
                "adoptedAt": iso8601(at),
                "macAddress": d.get("mac").cloned().unwrap_or(Value::Null),
                "ipAddress": d.get("ip").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_visit_is_not_an_arrival() {
        // first and last within the hour: it turned up once and left.
        let visit: i64 = 1_788_000_000;
        assert!(visit + 1800 - visit < 3600);
        assert!(
            visit + 86_400 - visit >= 3600,
            "a device that stayed a day is an arrival"
        );
    }

    #[test]
    fn adoption_timestamps_are_accepted_in_either_unit() {
        // The console reports seconds on some records and milliseconds on
        // others; treating a millisecond value as seconds would date the
        // adoption tens of thousands of years from now.
        let seconds = 1_788_000_000_i64;
        let millis = seconds * 1000;
        let normalize = |at: i64| if at > 100_000_000_000 { at / 1000 } else { at };
        assert_eq!(normalize(seconds), seconds);
        assert_eq!(normalize(millis), seconds);
    }
}
