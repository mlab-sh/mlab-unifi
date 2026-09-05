//! `clients` — what is connected to a site, and what ever was.
//!
//! Two different questions, two different surfaces. The documented API answers
//! "who is connected right now". The asset inventory — every client the console
//! has ever seen, with the date it first appeared — only exists on the legacy
//! surface, so `--all` joins the two on the MAC address.

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::cli::{Ctx, ListArgs};
use crate::enrich::{self, fingerprint, oui};
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
        /// Ask mlab.sh for the vendor of the addresses nothing local could name
        #[arg(long)]
        allow_web: bool,
        /// Confidence below which an identification is only reported, not asserted
        #[arg(long, default_value_t = 90, value_name = "0-100")]
        min_score: u8,
        /// Skip identity resolution entirely
        #[arg(long)]
        no_resolve: bool,
    },
    /// Show one client, by integration id or by MAC address
    Get {
        #[arg(value_name = "ID|MAC")]
        id: String,
    },
    /// Grant guest access to a client
    Authorize { id: String },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: ClientCmd) -> Result<()> {
    unifi::local_only(c, "clients")?;
    let site = site::resolve(c, &ctx.profile.site).await?;

    match cmd {
        ClientCmd::List {
            page,
            all,
            allow_web,
            min_score,
            no_resolve,
        } => {
            let opts = Identify {
                allow_web,
                min_score,
                resolve: !no_resolve,
            };
            list(c, ctx, &site, &page, all, &opts).await
        }
        ClientCmd::Get { id } => {
            let id = resolve_client(c, &site, &id).await?;
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

/// How much identity work `--all` should do.
struct Identify {
    allow_web: bool,
    min_score: u8,
    resolve: bool,
}

async fn list(
    c: &Client,
    ctx: &Ctx,
    site: &str,
    page: &ListArgs,
    all: bool,
    opts: &Identify,
) -> Result<()> {
    let path = format!("/sites/{}/clients", esc(site));
    let active = ui::spin(
        "Listing clients",
        c.list(&path, &[], page.offset, page.limit),
    )
    .await?;

    // The legacy list is what the inventory is built from, and it is also the
    // only place a fingerprint exists: the documented API carries none. So it
    // is fetched whenever either is wanted, in both modes.
    let mut known = Vec::new();
    let mut degraded = None;
    if all || opts.resolve {
        match legacy_users(c, site).await {
            Ok(k) => known = k,
            // Without it there is no inventory at all, but identity alone is a
            // bonus on the live list: losing it must not lose the listing.
            Err(e) if all => return Err(e),
            Err(e) => degraded = Some(e.to_string()),
        }
    }

    let mut rows = if all {
        inventory(&active, &known)
    } else {
        active.clone()
    };

    let mut report = if opts.resolve && !known.is_empty() {
        identify(c, ctx, &mut rows, &known, opts).await
    } else {
        Report::default()
    };
    if report.error.is_none() {
        report.error = degraded;
    }

    let cols = match (all, report.resolved) {
        (true, true) => render::IDENTITY_COLS,
        (true, false) => render::INVENTORY_COLS,
        (false, true) => render::LIVE_IDENTITY_COLS,
        (false, false) => render::CLIENT_COLS,
    };

    render::heading(if all { "Client inventory" } else { "Clients" });
    render::list(&rows, cols);
    render::count(rows.len(), "client");

    if !render::is_json() {
        if all {
            let live = rows
                .iter()
                .filter(|r| r["activeNow"] == Value::Bool(true))
                .count();
            ui::info(&format!(
                "{live} connected now, {} seen before",
                rows.len() - live
            ));
        }
        for line in report.notes(opts) {
            ui::info(&line);
        }
    }
    Ok(())
}

/// Accept a MAC address wherever an integration id is expected.
///
/// The id is a UUID nobody reads off a screen, and the listing drops that
/// column once identities are resolved. The MAC is on every row and is the key
/// people actually have, so take either.
async fn resolve_client(c: &Client, site: &str, want: &str) -> Result<String> {
    let Some(mac) = as_mac(want) else {
        return Ok(want.to_string());
    };

    let path = format!("/sites/{}/clients", esc(site));
    let clients = ui::spin("Looking up the client", c.list(&path, &[], 0, None)).await?;

    for cl in &clients {
        if mac_of(cl, "macAddress").as_deref() == Some(mac.as_str()) {
            return cl
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("that client has no id");
        }
    }
    bail!("no client currently connected with MAC {mac}")
}

/// Six colon- or hyphen-separated hex pairs, normalized. Anything else is an id.
fn as_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(s.to_ascii_lowercase().replace('-', ":"))
}

/// Every client the console has ever seen, from the legacy surface.
async fn legacy_users(c: &Client, site: &str) -> Result<Vec<Value>> {
    let legacy_site = site::resolve_legacy(c, site).await?;
    ui::spin(
        "Listing every known client",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/user", esc(&legacy_site)),
            &[],
        ),
    )
    .await
}

/// What identity resolution achieved, so the table can be followed by a line
/// saying what is still not known.
#[derive(Default)]
struct Report {
    resolved: bool,
    unknown: usize,
    uncertain: usize,
    from_web: usize,
    error: Option<String>,
}

impl Report {
    fn notes(&self, opts: &Identify) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(e) = &self.error {
            out.push(format!("identity resolution incomplete: {e}"));
        }
        if self.from_web > 0 {
            out.push(format!(
                "{} vendor(s) resolved through mlab.sh",
                self.from_web
            ));
        }
        if self.uncertain > 0 {
            out.push(format!(
                "{} device(s) identified below {}% confidence, shown as reported",
                self.uncertain, opts.min_score
            ));
        }
        if self.unknown > 0 {
            let hint = if opts.allow_web {
                "no vendor found"
            } else {
                "run with --allow-web to resolve their vendor through mlab.sh"
            };
            out.push(format!("{} device(s) unidentified: {hint}", self.unknown));
        }
        out
    }
}

/// Resolve an identity for every row, and record what is left unknown.
async fn identify(
    c: &Client,
    ctx: &Ctx,
    rows: &mut [Value],
    known: &[Value],
    opts: &Identify,
) -> Report {
    let mut report = Report::default();

    let table = match fingerprint::load(c, &ctx.profile.host, false).await {
        Ok(t) => t,
        Err(e) => {
            // The lookup table lives on the undocumented v2 surface. Losing it
            // must cost the identity columns, not the inventory.
            report.error = Some(e.to_string());
            return report;
        }
    };
    report.resolved = true;

    let by_mac: HashMap<String, &Value> = known
        .iter()
        .filter_map(|k| mac_of(k, "mac").map(|m| (m, k)))
        .collect();

    // First pass: what the console already knows.
    let mut ids: Vec<fingerprint::Identity> = rows
        .iter()
        .map(|r| {
            let mac = r["macAddress"].as_str().unwrap_or_default();
            let mut id = by_mac
                .get(mac)
                .map(|rec| fingerprint::resolve(&table, rec))
                .unwrap_or_default();
            // The console resolves some OUIs itself and reports the vendor as
            // a plain string; take it when the fingerprint gave none.
            if id.vendor.is_none() {
                id.vendor = by_mac
                    .get(mac)
                    .and_then(|rec| rec.get("oui"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
            }
            id
        })
        .collect();

    // Second pass: only the addresses nothing local could name, and only those
    // a vendor table can answer for. A randomized address has no registration
    // behind it, so asking would leak an identifier for a guaranteed miss.
    let gaps: BTreeSet<String> = rows
        .iter()
        .zip(&ids)
        .filter(|(_, id)| id.is_unknown())
        .filter_map(|(r, _)| {
            let mac = r["macAddress"].as_str()?;
            (!enrich::is_randomized(mac)).then(|| enrich::oui_of(mac))?
        })
        .collect();

    if !gaps.is_empty() {
        let outcome = oui::resolve(&gaps, opts.allow_web).await;
        report.from_web = outcome.queried;
        if report.error.is_none() {
            report.error = outcome.error;
        }

        for (r, id) in rows.iter().zip(ids.iter_mut()) {
            if !id.is_unknown() {
                continue;
            }
            let Some(entry) = r["macAddress"]
                .as_str()
                .and_then(enrich::oui_of)
                .and_then(|o| outcome.found.get(&o))
            else {
                continue;
            };
            id.vendor = entry.vendor.clone();
            if let Some(v) = &entry.virtualization {
                id.device = Some(format!("{v} virtual interface"));
            }
        }
    }

    // Write the identities onto the rows, and count what is left.
    for (r, id) in rows.iter_mut().zip(&ids) {
        let mac = r["macAddress"].as_str().unwrap_or_default().to_string();
        if id.is_unknown() {
            report.unknown += 1;
        } else if id.is_uncertain(opts.min_score) {
            report.uncertain += 1;
        }

        let obj = r.as_object_mut().expect("inventory rows are objects");
        obj.insert(
            "vendor".into(),
            match (&id.vendor, enrich::is_randomized(&mac)) {
                (Some(v), _) => json!(v),
                // Not a gap in the data: the device is hiding on purpose, and
                // saying so is more useful than an empty cell.
                (None, true) => json!("(randomized)"),
                (None, false) => Value::Null,
            },
        );
        obj.insert(
            "device".into(),
            id.device.clone().map(Value::from).unwrap_or(Value::Null),
        );
        // A display-only column: a guess stays visible but marked, so the table
        // never asserts what the console itself does not stand behind. Skipped
        // in JSON mode, where `identityCertain` carries the same fact cleanly.
        if !render::is_json() {
            if let Some(d) = &id.device {
                let label = if id.is_uncertain(opts.min_score) {
                    format!("{d} ?")
                } else {
                    d.clone()
                };
                obj.insert("deviceLabel".into(), json!(label));
            }
        }
        obj.insert(
            "os".into(),
            id.os.clone().map(Value::from).unwrap_or(Value::Null),
        );
        obj.insert(
            "family".into(),
            id.family.clone().map(Value::from).unwrap_or(Value::Null),
        );
        obj.insert(
            "confidence".into(),
            id.confidence.map(Value::from).unwrap_or(Value::Null),
        );
        obj.insert(
            "identityCertain".into(),
            json!(!id.is_uncertain(opts.min_score)),
        );
    }

    report
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
    fn a_mac_is_recognised_in_either_notation_and_an_id_is_left_alone() {
        assert_eq!(
            as_mac("88:A2:9E:5F:36:85").as_deref(),
            Some("88:a2:9e:5f:36:85")
        );
        assert_eq!(
            as_mac("88-a2-9e-5f-36-85").as_deref(),
            Some("88:a2:9e:5f:36:85")
        );
        assert_eq!(
            as_mac("bcbeac5b-c25a-3240-8188-6a0f392977af"),
            None,
            "a UUID is an id"
        );
        assert_eq!(as_mac("88:a2:9e:5f:36"), None, "five groups is not a MAC");
        assert_eq!(as_mac("zz:a2:9e:5f:36:85"), None, "not hex");
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
