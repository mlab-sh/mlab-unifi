//! `clients` — what is connected to a site, and what ever was.
//!
//! Two different questions, two different surfaces. The documented API answers
//! "who is connected right now". The asset inventory — every client the console
//! has ever seen, with the date it first appeared — only exists on the legacy
//! surface, so `--all` joins the two on the MAC address.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::cli::{Ctx, ListArgs};
use crate::ui::{self, render};
use crate::unifi::{self, esc, iso8601, site, Client, Surface};

#[derive(Subcommand, Debug)]
pub enum ClientCmd {
    /// List clients
    List {
        #[command(flatten)]
        page: ListArgs,
        /// Every client the console has ever seen, not only those connected now
        #[arg(long)]
        all: bool,
    },
    /// Show one client
    Get { id: String },
    /// Grant guest access to a client
    Authorize { id: String },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: ClientCmd) -> Result<()> {
    unifi::local_only(c, "clients")?;
    let site = site::resolve(c, &ctx.profile.site).await?;

    match cmd {
        ClientCmd::List { page, all } => list(c, &site, &page, all).await,
        ClientCmd::Get { id } => {
            let path = format!("/sites/{}/clients/{}", esc(&site), esc(&id));
            let v = ui::spin("Reading the client", c.get_one(&path)).await?;
            render::heading(&render::name_of(&v, &id));
            render::one(&v);
            Ok(())
        }
        ClientCmd::Authorize { id } => {
            let path = format!("/sites/{}/clients/{}/actions", esc(&site), esc(&id));
            let body = json!({ "action": "AUTHORIZE_GUEST_ACCESS" });
            let v = ui::spin(
                "Authorizing",
                c.request(Method::POST, &path, &[], Some(&body)),
            )
            .await?;
            ui::success(&format!("guest access granted to {id}"));
            render::one(&v);
            Ok(())
        }
    }
}

async fn list(c: &Client, site: &str, page: &ListArgs, all: bool) -> Result<()> {
    let path = format!("/sites/{}/clients", esc(site));
    let active = ui::spin(
        "Listing clients",
        c.list(&path, &[], page.offset, page.limit),
    )
    .await?;

    if !all {
        render::heading("Clients");
        render::list(&active, render::CLIENT_COLS);
        render::count(active.len(), "client");
        return Ok(());
    }

    let legacy_site = site::resolve_legacy(c, site).await?;
    let known = ui::spin(
        "Listing every known client",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/user", esc(&legacy_site)),
            &[],
        ),
    )
    .await?;

    let rows = inventory(&active, &known);
    let live = rows
        .iter()
        .filter(|r| r["activeNow"] == Value::Bool(true))
        .count();

    render::heading("Client inventory");
    render::list(&rows, render::INVENTORY_COLS);
    render::count(rows.len(), "client");
    if !render::is_json() {
        ui::info(&format!(
            "{live} connected now, {} seen before",
            rows.len() - live
        ));
    }
    Ok(())
}

/// Join the live list onto the historical one, keyed by MAC.
///
/// Every known client becomes a row; `activeNow` says whether it is also in the
/// live list. An active client missing from the history still gets a row — a
/// silently dropped device is the one bug an inventory cannot afford.
fn inventory(active: &[Value], known: &[Value]) -> Vec<Value> {
    let by_mac: HashMap<String, &Value> = active
        .iter()
        .filter_map(|v| mac_of(v, "macAddress").map(|m| (m, v)))
        .collect();

    let mut seen: HashSet<String> = HashSet::new();
    let mut rows: Vec<Value> = known
        .iter()
        .filter_map(|k| {
            let mac = mac_of(k, "mac")?;
            seen.insert(mac.clone());
            Some(record(&mac, by_mac.get(&mac).copied(), Some(k)))
        })
        .collect();

    for (mac, a) in &by_mac {
        if !seen.contains(mac) {
            rows.push(record(mac, Some(a), None));
        }
    }

    // Connected first, then most recently seen: the top of the list is what
    // matters now, the bottom is what has drifted away.
    rows.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["activeNow"] == Value::Bool(true),
                v["lastSeen"].as_str().unwrap_or("").to_string(),
            )
        };
        key(b).cmp(&key(a))
    });
    rows
}

/// One inventory row, from whichever of the two sources has the field.
fn record(mac: &str, active: Option<&Value>, known: Option<&Value>) -> Value {
    let live = |k: &str| {
        active
            .and_then(|v| v.get(k))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let hist = |k: &str| {
        known
            .and_then(|v| v.get(k))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let stamp = |k: &str| {
        known
            .and_then(|v| v.get(k))
            .and_then(Value::as_i64)
            .filter(|t| *t > 0)
            .map(iso8601)
            .unwrap_or_default()
    };

    let name = [live("name"), hist("name"), hist("hostname")]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_string();

    let kind = match live("type") {
        "" => match known
            .and_then(|v| v.get("is_wired"))
            .and_then(Value::as_bool)
        {
            Some(true) => "WIRED",
            Some(false) => "WIRELESS",
            None => "",
        },
        t => t,
    };

    json!({
        "name": name,
        "activeNow": active.is_some(),
        "ipAddress": if live("ipAddress").is_empty() { hist("last_ip") } else { live("ipAddress") },
        "macAddress": mac,
        "type": kind,
        "network": hist("last_connection_network_name"),
        "uplink": hist("last_uplink_name"),
        "guest": known.and_then(|v| v.get("is_guest")).and_then(Value::as_bool).unwrap_or(false),
        "firstSeen": stamp("first_seen"),
        "lastSeen": stamp("last_seen"),
        "id": live("id"),
    })
}

/// A MAC in one canonical case, so the two surfaces join reliably.
fn mac_of(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active(mac: &str, name: &str) -> Value {
        json!({"macAddress": mac, "name": name, "ipAddress": "10.0.0.2", "type": "WIRELESS", "id": "abc"})
    }
    fn known(mac: &str, name: &str, first: i64, last: i64) -> Value {
        json!({"mac": mac, "hostname": name, "is_wired": true, "last_ip": "10.0.0.9",
               "first_seen": first, "last_seen": last})
    }

    #[test]
    fn every_known_client_gets_a_row_flagged_by_liveness() {
        let rows = inventory(
            &[active("aa:bb:cc:00:00:01", "live")],
            &[
                known("aa:bb:cc:00:00:01", "live", 1, 200),
                known("aa:bb:cc:00:00:02", "gone", 1, 100),
            ],
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0]["activeNow"],
            json!(true),
            "connected clients sort first"
        );
        assert_eq!(rows[1]["activeNow"], json!(false));
    }

    #[test]
    fn the_live_record_wins_on_fields_both_sources_have() {
        let rows = inventory(
            &[active("aa:bb:cc:00:00:01", "live")],
            &[known("aa:bb:cc:00:00:01", "old", 1, 2)],
        );
        assert_eq!(rows[0]["name"], json!("live"));
        assert_eq!(rows[0]["ipAddress"], json!("10.0.0.2"));
        assert_eq!(
            rows[0]["type"],
            json!("WIRELESS"),
            "the live type wins over is_wired"
        );
    }

    #[test]
    fn an_active_client_absent_from_history_is_not_dropped() {
        let rows = inventory(&[active("aa:bb:cc:00:00:09", "orphan")], &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["activeNow"], json!(true));
        assert_eq!(
            rows[0]["firstSeen"],
            json!(""),
            "no history means no dates, not a fake one"
        );
    }

    #[test]
    fn macs_join_across_surfaces_whatever_their_case() {
        let rows = inventory(
            &[active("AA:BB:CC:00:00:01", "live")],
            &[known("aa:bb:cc:00:00:01", "same", 1, 2)],
        );
        assert_eq!(rows.len(), 1, "one device, not two");
        assert_eq!(rows[0]["activeNow"], json!(true));
    }

    #[test]
    fn epoch_stamps_become_sortable_iso_dates() {
        let rows = inventory(
            &[],
            &[known(
                "aa:bb:cc:00:00:01",
                "x",
                1_759_148_439,
                1_788_597_337,
            )],
        );
        assert_eq!(rows[0]["firstSeen"], json!("2025-09-29T12:20:39Z"));
        assert_eq!(rows[0]["lastSeen"], json!("2026-09-05T08:35:37Z"));
    }
}
