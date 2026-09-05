//! `wifi` — the radio side: hardening, neighbourhood, impostors, airtime.
//!
//! One measurement limit shapes three of the four views and is repeated in the
//! output rather than left implicit: **the console does not sweep the
//! spectrum**. An access point reports what it overhears while sitting on its
//! own operating channel, so the neighbour list only ever covers channels that
//! overlap yours. "Nothing found" therefore means "nothing on my channels".

use std::collections::HashSet;

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::enrich::fingerprint;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

/// Said under every view built on the neighbour list.
const SCAN_CAVEAT: &str = "the console does not sweep the spectrum: it only hears what overlaps \
     the channels its own radios sit on, so anything found here is a floor, never a survey";

/// Fingerprint families that describe a device which can bridge a network.
const AP_FAMILIES: [&str; 6] = [
    "Wireless Access Point",
    "Wireless Router",
    "Router",
    "Firewall",
    "Network Equipment",
    "Smart Gateway",
];

#[derive(Subcommand, Debug)]
pub enum WifiCmd {
    /// How each SSID is configured, and what that leaves open
    Hardening,
    /// Every access point the radios can hear
    #[command(alias = "neighbors")]
    Neighbours,
    /// Impostor SSIDs, and access points bridged onto your own network
    Rogue {
        /// Confidence below which a fingerprint is not treated as an identification
        #[arg(long, default_value_t = 90, value_name = "0-100")]
        min_score: u8,
    },
    /// Who is using the air on each radio, and how much of it is not you
    Airtime,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<WifiCmd>) -> Result<()> {
    unifi::local_only(c, "wifi")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    match cmd.unwrap_or(WifiCmd::Hardening) {
        WifiCmd::Hardening => hardening(c, &legacy).await,
        WifiCmd::Neighbours => neighbours(c, &legacy).await,
        WifiCmd::Rogue { min_score } => rogue(c, ctx, &legacy, min_score).await,
        WifiCmd::Airtime => airtime(c, &legacy).await,
    }
}

// ---- 1. hardening -----------------------------------------------------------

async fn hardening(c: &Client, legacy: &str) -> Result<()> {
    let wlans = wlanconf(c, legacy).await?;

    let rows: Vec<Value> = wlans
        .iter()
        .map(|w| {
            let s = |k: &str| {
                w.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let b = |k: &str| w.get(k).and_then(Value::as_bool).unwrap_or(false);
            let psk = w
                .get("x_passphrase")
                .and_then(Value::as_str)
                .unwrap_or_default();

            json!({
                "name": s("name"),
                "security": format!("{}/{}", s("wpa_mode"), s("wpa_enc")),
                "wpa3": match (b("wpa3_support"), b("wpa3_transition")) {
                    (true, true) => "transition",
                    (true, false) => "required",
                    _ => "no",
                },
                "pmf": s("pmf_mode"),
                // Never the value: its length and the classes it draws on are
                // what a strength check needs, and all it is entitled to.
                "psk": describe_secret(psk),
                "pskLength": psk.chars().count(),
                "isolation": on_off(b("l2_isolation")),
                "guest": b("is_guest"),
                "enabled": w.get("enabled").cloned().unwrap_or(Value::Null),
                "hidden": b("hide_ssid"),
                "macFilter": b("mac_filter_enabled"),
                "privateKeys": b("private_preshared_keys_enabled"),
                "groupRekeySeconds": w.get("group_rekey").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    render::heading("Wireless networks");
    render::list(&rows, render::WLAN_COLS);
    render::count(rows.len(), "SSID");

    if render::is_json() {
        return Ok(());
    }
    for r in &rows {
        let name = r["name"].as_str().unwrap_or_default();
        if r["wpa3"] == json!("transition") {
            ui::warning(&format!(
                "{name}: WPA3 is in transition mode, so a client can still negotiate WPA2 \
                 and none of WPA3's protections are guaranteed"
            ));
        }
        if r["pmf"] != json!("required") {
            ui::warning(&format!(
                "{name}: management frames are not protected ({}), which is what makes \
                 deauthentication work",
                r["pmf"].as_str().unwrap_or("unset")
            ));
        }
        if r["pskLength"].as_u64().unwrap_or(99) < 12 {
            ui::warning(&format!(
                "{name}: the pre-shared key is short enough to be worth attacking offline \
                 once a handshake is captured"
            ));
        }
        if r["groupRekeySeconds"] == json!(0) {
            ui::info(&format!("{name}: the group key is never rotated"));
        }
        if r["privateKeys"] == json!(false) {
            ui::info(&format!(
                "{name}: one key shared by every device, so changing it means reprovisioning \
                 all of them"
            ));
        }
        // Reported, but never as a point in favour: both are trivially defeated
        // and crediting them as protections misleads.
        if r["hidden"] == json!(true) {
            ui::info(&format!(
                "{name}: SSID hidden, which is not a security control"
            ));
        }
        if r["macFilter"] == json!(true) {
            ui::info(&format!(
                "{name}: MAC filtering on, which is not a security control"
            ));
        }
    }
    Ok(())
}

/// Length and character classes of a secret. Never its value.
fn describe_secret(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let classes = [
        s.chars().any(|c| c.is_lowercase()),
        s.chars().any(|c| c.is_uppercase()),
        s.chars().any(|c| c.is_numeric()),
        s.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    format!("{} ch, {classes} class", s.chars().count())
}

// ---- 2. neighbours ----------------------------------------------------------

async fn neighbours(c: &Client, legacy: &str) -> Result<()> {
    let seen = rogueap(c, legacy).await?;

    let mut rows: Vec<Value> = seen.iter().map(neighbour_row).collect();
    // Closest first: signal is what decides whether a neighbour matters.
    rows.sort_by_key(|r| -r["signal"].as_i64().unwrap_or(-127));

    render::heading("Access points in range");
    render::list(&rows, render::NEIGHBOUR_COLS);
    render::count(rows.len(), "access point");

    if render::is_json() {
        return Ok(());
    }

    let count = |f: &dyn Fn(&Value) -> bool| rows.iter().filter(|r| f(r)).count();
    let open = count(&|r| r["security"].as_str() == Some("Open"));
    let tkip = count(&|r| r["security"].as_str().is_some_and(|s| s.contains("TKIP")));
    if open > 0 {
        ui::info(&format!("{open} open network(s) in range"));
    }
    if tkip > 0 {
        ui::info(&format!("{tkip} network(s) still accepting TKIP"));
    }

    let strongest = rows
        .first()
        .and_then(|r| r["signal"].as_i64())
        .unwrap_or(-127);
    ui::info(&format!(
        "strongest neighbour at {strongest} dBm{}",
        if strongest < -70 {
            ", all of them far enough to be background noise"
        } else {
            ""
        }
    ));

    // Channel counts here would be an artefact: every neighbour is on one of
    // our channels by construction, so the distribution says nothing.
    ui::info(SCAN_CAVEAT);
    Ok(())
}

fn neighbour_row(x: &Value) -> Value {
    let s = |k: &str| {
        x.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    json!({
        "essid": s("essid"),
        "bssid": s("bssid"),
        "band": match s("band").as_str() { "ng" => "2.4", "na" => "5", other => other },
        "channel": x.get("channel").cloned().unwrap_or(Value::Null),
        "width": x.get("bw").cloned().unwrap_or(Value::Null),
        "security": s("security"),
        "signal": x.get("signal").cloned().unwrap_or(Value::Null),
        "vendor": s("oui"),
        "seenSecondsAgo": x.get("age").cloned().unwrap_or(Value::Null),
    })
}

// ---- 3. impostors and bridged access points ---------------------------------

async fn rogue(c: &Client, ctx: &Ctx, legacy: &str, min_score: u8) -> Result<()> {
    let seen = rogueap(c, legacy).await?;
    let wlans = wlanconf(c, legacy).await?;
    let clients = legacy_users(c, legacy).await.unwrap_or_default();

    let mine: HashSet<String> = wlans
        .iter()
        .filter_map(|w| w.get("name").and_then(Value::as_str).map(str::to_string))
        .collect();

    // An impostor broadcasts a name that is ours. Weaker security on it is the
    // classic setup: the client joins the open copy without noticing.
    let twins: Vec<Value> = seen
        .iter()
        .filter(|x| {
            x.get("essid")
                .and_then(Value::as_str)
                .is_some_and(|e| mine.contains(e))
        })
        .map(neighbour_row)
        .collect();

    // A bridged access point usually carries its wired address within a few
    // units of the BSSID it broadcasts, same vendor prefix.
    let known: HashSet<String> = clients
        .iter()
        .filter_map(|x| {
            x.get("mac")
                .and_then(Value::as_str)
                .map(|m| m.replace(':', "").to_lowercase())
        })
        .collect();
    let adjacent: Vec<Value> = seen
        .iter()
        .filter(|x| {
            x.get("bssid")
                .and_then(Value::as_str)
                .map(|b| b.replace(':', "").to_lowercase())
                .is_some_and(|b| known.iter().any(|k| mac_adjacent(&b, k)))
        })
        .map(neighbour_row)
        .collect();

    // The path that does not depend on the radio at all, and so is not limited
    // to our own channels: a wired client the console fingerprinted as a device
    // that bridges networks.
    let bridges = wired_bridges(c, ctx, &clients, min_score).await;

    render::heading("Impostor SSIDs");
    if twins.is_empty() {
        if !render::is_json() {
            ui::info("no access point in range broadcasts one of your SSIDs");
        }
    } else {
        render::list(&twins, render::NEIGHBOUR_COLS);
    }

    render::heading("Access points bridged onto your network");
    if adjacent.is_empty() && bridges.is_empty() {
        if !render::is_json() {
            ui::info(
                "no BSSID sits next to a known wired address, and no wired client is \
                      fingerprinted as an access point",
            );
        }
    } else {
        if !adjacent.is_empty() {
            render::list(&adjacent, render::NEIGHBOUR_COLS);
        }
        if !bridges.is_empty() {
            render::list(&bridges, render::BRIDGE_COLS);
        }
    }

    if render::is_json() {
        return Ok(());
    }
    ui::info(SCAN_CAVEAT);
    ui::info(
        "an impostor has every reason to sit on a channel yours does not use, so a clean \
         result here is weak evidence; the wired check above does not share that limit",
    );
    Ok(())
}

/// Wired clients whose fingerprint says they can bridge a network.
async fn wired_bridges(c: &Client, ctx: &Ctx, clients: &[Value], min_score: u8) -> Vec<Value> {
    let Ok(table) = fingerprint::load(c, &ctx.profile.host, false).await else {
        return Vec::new();
    };

    clients
        .iter()
        .filter(|x| x.get("is_wired").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|x| {
            let id = fingerprint::resolve(&table, x);
            let family = id.family.clone()?;
            if !AP_FAMILIES.contains(&family.as_str()) || id.is_uncertain(min_score) {
                return None;
            }
            Some(json!({
                "name": x.get("name").or_else(|| x.get("hostname")).cloned().unwrap_or(Value::Null),
                "macAddress": x.get("mac").cloned().unwrap_or(Value::Null),
                "family": family,
                "device": id.device,
                "confidence": id.confidence,
                "lastIp": x.get("last_ip").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect()
}

/// Same vendor prefix, and the last byte within a small distance.
fn mac_adjacent(a: &str, b: &str) -> bool {
    if a.len() != 12 || b.len() != 12 || a[..9] != b[..9] || a == b {
        return false;
    }
    match (
        u32::from_str_radix(&a[9..], 16),
        u32::from_str_radix(&b[9..], 16),
    ) {
        (Ok(x), Ok(y)) => x.abs_diff(y) <= 8,
        _ => false,
    }
}

// ---- 4. airtime -------------------------------------------------------------

async fn airtime(c: &Client, legacy: &str) -> Result<()> {
    let devices = ui::spin(
        "Reading radio statistics",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/device", esc(legacy)),
            &[],
        ),
    )
    .await?;

    let mut rows = Vec::new();
    for d in &devices {
        let name = d.get("name").and_then(Value::as_str).unwrap_or_default();
        for r in d
            .get("radio_table_stats")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let n = |k: &str| r.get(k).and_then(Value::as_i64).unwrap_or(0);
            let total = n("cu_total");
            // What the radio spends on itself is not interference; the rest is.
            let others = (total - n("cu_self_rx") - n("cu_self_tx")).max(0);

            rows.push(json!({
                "device": name,
                "radio": match r.get("radio").and_then(Value::as_str).unwrap_or("") {
                    "ng" => "2.4", "na" => "5", "6e" => "6", other => other,
                },
                "channel": r.get("channel").cloned().unwrap_or(Value::Null),
                "width": r.get("bw").cloned().unwrap_or(Value::Null),
                "clients": n("num_sta"),
                "busyPct": total,
                "selfPct": n("cu_self_rx") + n("cu_self_tx"),
                "othersPct": others,
                "retriesPct": r.get("tx_retries_pct").cloned().unwrap_or(Value::Null),
                "txPower": n("tx_power"),
            }));
        }
    }

    render::heading("Airtime");
    render::list(&rows, render::AIRTIME_COLS);
    render::count(rows.len(), "radio");

    if render::is_json() {
        return Ok(());
    }
    if rows.is_empty() {
        ui::info("no device on this site reports radio statistics");
        return Ok(());
    }

    let worst = rows
        .iter()
        .max_by_key(|r| r["othersPct"].as_i64().unwrap_or(0))
        .unwrap();
    ui::info(&format!(
        "{} GHz on channel {} carries the most traffic that is not yours: {}% of the air",
        worst["radio"].as_str().unwrap_or("?"),
        worst["channel"],
        worst["othersPct"]
    ));

    if let Some(clean) = rows
        .iter()
        .filter(|r| {
            r["othersPct"].as_i64() == Some(0) && r["radio"].as_str() != worst["radio"].as_str()
        })
        .max_by_key(|r| r["clients"].as_i64().unwrap_or(0))
    {
        ui::info(&format!(
            "{} GHz is carrying nothing but your own traffic, so moving capable clients \
             there sidesteps the congestion instead of chasing a quieter channel",
            clean["radio"].as_str().unwrap_or("?")
        ));
    }

    ui::info(
        "busy minus your own share is interference; it does not say whether the cause is \
         deliberate. Sampling it over time, alongside clients reassociating together, is \
         what separates congestion from a deauthentication burst",
    );
    Ok(())
}

// ---- shared fetches ---------------------------------------------------------

async fn wlanconf(c: &Client, legacy: &str) -> Result<Vec<Value>> {
    ui::spin(
        "Reading wireless configuration",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/wlanconf", esc(legacy)),
            &[],
        ),
    )
    .await
}

async fn rogueap(c: &Client, legacy: &str) -> Result<Vec<Value>> {
    ui::spin(
        "Listing access points in range",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/rogueap", esc(legacy)),
            &[],
        ),
    )
    .await
}

async fn legacy_users(c: &Client, legacy: &str) -> Result<Vec<Value>> {
    c.list_on(
        Surface::Legacy,
        &format!("/s/{}/rest/user", esc(legacy)),
        &[],
    )
    .await
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bridged_access_point_sits_next_to_its_wired_address() {
        // Same vendor prefix, last byte a few units apart: one card, two roles.
        assert!(mac_adjacent("6c63f8000001", "6c63f8000003"));
        assert!(
            !mac_adjacent("6c63f8000001", "6c63f8000020"),
            "too far apart"
        );
        assert!(
            !mac_adjacent("6c63f8000001", "aabbcc000003"),
            "different vendor"
        );
        assert!(
            !mac_adjacent("6c63f8000001", "6c63f8000001"),
            "the same address is not a pair"
        );
        assert!(!mac_adjacent("short", "6c63f8000001"));
    }

    #[test]
    fn a_secret_is_described_by_shape_and_never_by_value() {
        let got = describe_secret("Tr0ub4dor&3");
        assert_eq!(got, "11 ch, 4 class");
        assert!(!got.contains("Tr0"), "the value never appears");
        assert_eq!(describe_secret("abcdefgh"), "8 ch, 1 class");
        assert_eq!(describe_secret(""), "");
    }
}
