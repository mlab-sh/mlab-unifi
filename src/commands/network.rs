//! `network` — the segmentation and the way in.
//!
//! Two questions this answers, both from configuration the console already
//! holds: how the site is cut up, and what can reach it from outside.
//!
//! The documented API lists networks and firewall zones but says nothing about
//! isolation, mDNS, UPnP or port forwards. Those live on the
//! [legacy surface](crate::unifi::Surface), so the commands join the two on the
//! network's UUID and degrade to the documented columns when it is missing.

use std::collections::HashMap;

use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Networks and how they are segmented
    List,
    /// One network in full, by name, VLAN id or network id
    Get {
        #[arg(value_name = "NAME|VLAN|ID")]
        which: String,
    },
    /// What can reach the site from outside: port forwards, UPnP, the WAN
    Exposure,
    /// Firewall zones and the networks in them
    Zones,
    /// Firewall policies, and what is measurably wrong with them
    Policies {
        /// Include the return rules the console generates for each of yours
        #[arg(long)]
        derived: bool,
        /// Include the system-defined rules as well
        #[arg(long)]
        all: bool,
    },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: NetworkCmd) -> Result<()> {
    unifi::local_only(c, "network")?;
    let site = site::resolve(c, &ctx.profile.site).await?;

    match cmd {
        NetworkCmd::List => list(c, &site).await,
        NetworkCmd::Get { which } => get(c, &site, &which).await,
        NetworkCmd::Exposure => exposure(c, &site).await,
        NetworkCmd::Zones => zones(c, &site).await,
        NetworkCmd::Policies { derived, all } => policies(c, &site, derived, all).await,
    }
}

// ---- the segmentation view --------------------------------------------------

async fn list(c: &Client, site: &str) -> Result<()> {
    let (rows, degraded) = networks(c, site).await?;

    render::heading("Networks");
    render::list(&rows, render::NETWORK_COLS);
    render::count(rows.len(), "network");

    if render::is_json() {
        return Ok(());
    }
    if let Some(e) = degraded {
        ui::warning(&format!("segmentation detail unavailable: {e}"));
        return Ok(());
    }

    // Observations, not verdicts. Isolation being off is normal on a site that
    // segments with firewall policy instead, so this points at what to read
    // next rather than calling it a finding.
    let count = |k: &str, want: &str| rows.iter().filter(|r| r[k].as_str() == Some(want)).count();
    let routed = count("isolation", "off");
    if routed > 0 {
        ui::info(&format!(
            "{routed} network(s) with isolation off: what crosses between them is decided \
             by firewall policy, see `network zones`"
        ));
    }
    let mdns = count("mdns", "on");
    if mdns > 0 {
        ui::info(&format!(
            "{mdns} network(s) propagate mDNS, which crosses VLAN boundaries"
        ));
    }
    let upnp = count("upnp", "on");
    if upnp > 0 {
        ui::warning(&format!(
            "{upnp} network(s) allow UPnP: any host on them can open a port by itself"
        ));
    }
    Ok(())
}

async fn get(c: &Client, site: &str, which: &str) -> Result<()> {
    let (rows, _) = networks(c, site).await?;
    let want = which.to_lowercase();

    let found = rows.iter().find(|r| {
        r["name"].as_str().map(str::to_lowercase).as_deref() == Some(want.as_str())
            || r["id"].as_str() == Some(which)
            || r["vlanId"].as_i64().map(|v| v.to_string()).as_deref() == Some(which)
    });

    match found {
        Some(v) => {
            render::heading(v["name"].as_str().unwrap_or(which));
            render::one(v);
            Ok(())
        }
        None => bail!(
            "no network named {which:?} (known: {})",
            rows.iter()
                .filter_map(|r| r["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The documented network list, enriched with the legacy segmentation fields.
///
/// Returns the rows plus, when the enrichment failed, why.
async fn networks(c: &Client, site: &str) -> Result<(Vec<Value>, Option<String>)> {
    let path = format!("/sites/{}/networks", esc(site));
    let base = ui::spin("Listing networks", c.list(&path, &[], 0, None)).await?;

    let zone_names: HashMap<String, String> = match zone_list(c, site).await {
        Ok(z) => z
            .iter()
            .filter_map(|v| {
                Some((
                    v.get("id")?.as_str()?.to_string(),
                    v.get("name")?.as_str()?.to_string(),
                ))
            })
            .collect(),
        Err(_) => HashMap::new(),
    };

    let (detail, degraded) = match legacy_networks(c, site).await {
        Ok(d) => (d, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    // The two surfaces agree on the network's UUID: `external_id` on one side,
    // `id` on the other.
    let by_id: HashMap<String, &Value> = detail
        .iter()
        .filter_map(|d| Some((d.get("external_id")?.as_str()?.to_string(), d)))
        .collect();

    let rows = base
        .iter()
        .map(|n| {
            let id = n.get("id").and_then(Value::as_str).unwrap_or_default();
            let d = by_id.get(id);
            let flag = |k: &str, on: &'static str, off: &'static str| match d
                .and_then(|v| v.get(k))
                .and_then(Value::as_bool)
            {
                Some(true) => json!(on),
                Some(false) => json!(off),
                None => Value::Null,
            };
            let text = |k: &str| {
                d.and_then(|v| v.get(k))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(Value::from)
                    .unwrap_or(Value::Null)
            };

            let mut row = n.clone();
            let obj = row.as_object_mut().expect("networks are objects");
            obj.insert(
                "zone".into(),
                n.get("zoneId")
                    .and_then(Value::as_str)
                    .and_then(|z| zone_names.get(z))
                    .map(|s| json!(s))
                    .unwrap_or(Value::Null),
            );
            obj.insert("subnet".into(), text("ip_subnet"));
            obj.insert("purpose".into(), text("purpose"));
            obj.insert(
                "isolation".into(),
                flag("network_isolation_enabled", "on", "off"),
            );
            obj.insert(
                "internet".into(),
                flag("internet_access_enabled", "allowed", "blocked"),
            );
            obj.insert("mdns".into(), flag("mdns_enabled", "on", "off"));
            obj.insert("upnp".into(), flag("upnp_lan_enabled", "on", "off"));
            obj.insert("dhcp".into(), flag("dhcpd_enabled", "on", "off"));
            obj.insert("dhcpGuard".into(), flag("dhcpguard_enabled", "on", "off"));
            row
        })
        .collect();

    Ok((rows, degraded))
}

// ---- the way in -------------------------------------------------------------

async fn exposure(c: &Client, site: &str) -> Result<()> {
    let legacy_site = site::resolve_legacy(c, site).await?;

    let forwards = ui::spin(
        "Reading port forwards",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/portforward", esc(&legacy_site)),
            &[],
        ),
    )
    .await?;

    let rows: Vec<Value> = forwards
        .iter()
        .map(|f| {
            let s = |k: &str| {
                f.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let b = |k: &str| f.get(k).and_then(Value::as_bool).unwrap_or(false);
            json!({
                "name": s("name"),
                "proto": s("proto"),
                "wanPort": s("dst_port"),
                "target": format!("{}:{}", s("fwd"), s("fwd_port")),
                "enabled": b("enabled"),
                "log": if b("log") { "on" } else { "off" },
                // Without a source restriction the rule accepts the whole
                // internet, which is the default and rarely intended.
                "source": if b("src_limiting_enabled") { "restricted" } else { "any" },
                "interface": s("pfwd_interface"),
            })
        })
        .collect();

    let wan = wan_context(c, &legacy_site).await;
    render::heading("Inbound exposure");
    if let Some(w) = &wan {
        render::one(w);
    }
    render::list(&rows, render::FORWARD_COLS);
    render::count(rows.len(), "port forward");

    if render::is_json() {
        return Ok(());
    }

    // A private WAN address changes what every rule below means, so it is said
    // before them rather than after.
    if let Some(w) = &wan {
        if w["wanIpScope"] == json!("private") {
            ui::info(&format!(
                "the WAN address {} is private: this console sits behind another router, so \
                 a forward here only publishes anything if that router forwards to it too",
                w["wanIp"].as_str().unwrap_or_default()
            ));
        }
    }

    let active: Vec<&Value> = rows
        .iter()
        .filter(|r| r["enabled"] == json!(true))
        .collect();
    let unlogged = active.iter().filter(|r| r["log"] == json!("off")).count();
    let open = active
        .iter()
        .filter(|r| r["source"] == json!("any"))
        .count();

    if active.len() < rows.len() {
        ui::info(&format!(
            "{} rule(s) present but disabled",
            rows.len() - active.len()
        ));
    }
    if unlogged > 0 {
        ui::warning(&format!(
            "{unlogged} active forward(s) with logging off: traffic accepted through them \
             leaves no trace to investigate later"
        ));
    }
    if open > 0 {
        ui::warning(&format!(
            "{open} active forward(s) accept any source address"
        ));
    }
    if active.is_empty() {
        ui::info("no port forward is active: nothing is published inbound this way");
    }
    Ok(())
}

/// The WAN side, for context on what the forwards are exposed to.
async fn wan_context(c: &Client, legacy_site: &str) -> Option<Value> {
    let health = c
        .list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/health", esc(legacy_site)),
            &[],
        )
        .await
        .ok()?;

    let wan = health
        .iter()
        .find(|h| h.get("subsystem").and_then(Value::as_str) == Some("wan"))?;
    let s = |k: &str| {
        wan.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };

    let ip = s("wan_ip");
    Some(json!({
        "wanIp": ip,
        "wanIpScope": if is_private(&ip) { "private" } else { "public" },
        "isp": s("isp_name"),
        "asn": wan.get("asn").cloned().unwrap_or(Value::Null),
        "status": s("status"),
    }))
}

/// Whether an address is one the internet does not route to.
///
/// RFC 1918, plus the carrier-grade NAT range: on all of them the console sits
/// behind another router, and a forward defined here only publishes anything if
/// that router forwards to it too.
fn is_private(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 {
        return false;
    }
    match (o[0], o[1]) {
        (10, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        (100, b) if (64..=127).contains(&b) => true,
        (127, _) => true,
        _ => false,
    }
}

// ---- zones ------------------------------------------------------------------

async fn zones(c: &Client, site: &str) -> Result<()> {
    let zones = zone_list(c, site).await?;
    let (nets, _) = networks(c, site).await?;

    let mut names: HashMap<String, String> = nets
        .iter()
        .filter_map(|n| {
            Some((
                n.get("id")?.as_str()?.to_string(),
                n.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect();

    // The documented list covers LAN networks only, so WAN and VPN networks
    // would otherwise show up in a zone as bare UUIDs.
    if let Ok(detail) = legacy_networks(c, site).await {
        for d in &detail {
            if let (Some(id), Some(name)) = (
                d.get("external_id").and_then(Value::as_str),
                d.get("name").and_then(Value::as_str),
            ) {
                names
                    .entry(id.to_string())
                    .or_insert_with(|| name.to_string());
            }
        }
    }

    let rows: Vec<Value> = zones
        .iter()
        .map(|z| {
            let members: Vec<String> = z
                .get("networkIds")
                .and_then(Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|i| i.as_str())
                        .map(|i| names.get(i).cloned().unwrap_or_else(|| i.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "name": z.get("name").cloned().unwrap_or(Value::Null),
                "origin": z.pointer("/metadata/origin").cloned().unwrap_or(Value::Null),
                "networks": members,
                "id": z.get("id").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    render::heading("Firewall zones");
    render::list(&rows, render::ZONE_COLS);
    render::count(rows.len(), "zone");

    if !render::is_json() {
        let empty = rows
            .iter()
            .filter(|r| r["networks"].as_array().is_some_and(|a| a.is_empty()));
        let names: Vec<&str> = empty.filter_map(|r| r["name"].as_str()).collect();
        if !names.is_empty() {
            ui::info(&format!(
                "{} zone(s) hold no network: {}",
                names.len(),
                names.join(", ")
            ));
        }
    }
    Ok(())
}

async fn zone_list(c: &Client, site: &str) -> Result<Vec<Value>> {
    let path = format!("/sites/{}/firewall/zones", esc(site));
    ui::spin("Listing firewall zones", c.list(&path, &[], 0, None)).await
}

async fn legacy_networks(c: &Client, site: &str) -> Result<Vec<Value>> {
    let legacy_site = site::resolve_legacy(c, site).await?;
    ui::spin(
        "Reading segmentation",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/networkconf", esc(&legacy_site)),
            &[],
        ),
    )
    .await
}

// ---- firewall policies ------------------------------------------------------

/// Rule hygiene: what can be established from the rules themselves.
///
/// Everything here is a property of a single rule or of an exact pair, never of
/// an ordering. See [`ORDER_CAVEAT`] for why.
async fn policies(c: &Client, site: &str, derived: bool, all: bool) -> Result<()> {
    let path = format!("/sites/{}/firewall/policies", esc(site));
    let raw = ui::spin("Listing firewall policies", c.list(&path, &[], 0, None)).await?;

    let zones = zone_list(c, site).await.unwrap_or_default();
    let zone_names: HashMap<String, String> = zones
        .iter()
        .filter_map(|z| {
            Some((
                z.get("id")?.as_str()?.to_string(),
                z.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect();
    // A zone with no network can never match anything, so a rule pointing at
    // one is dead by construction rather than by ordering.
    let empty_zones: HashMap<String, String> = zones
        .iter()
        .filter(|z| {
            z.get("networkIds")
                .and_then(Value::as_array)
                .is_some_and(|a| a.is_empty())
        })
        .filter_map(|z| {
            Some((
                z.get("id")?.as_str()?.to_string(),
                z.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect();

    let lists = matching_lists(c, site).await;

    let keep = |origin: &str| match origin {
        "USER_DEFINED" => true,
        "DERIVED" => derived || all,
        _ => all,
    };

    let rows: Vec<Value> = raw
        .iter()
        .filter(|p| keep(p.pointer("/metadata/origin").and_then(Value::as_str).unwrap_or("")))
        .map(|p| {
            let side = |which: &str| {
                let s = p.get(which).cloned().unwrap_or(Value::Null);
                let zone_id = s.get("zoneId").and_then(Value::as_str).unwrap_or_default().to_string();
                let zone = zone_names.get(&zone_id).cloned().unwrap_or_else(|| zone_id.clone());
                let filter = describe_filter(s.get("trafficFilter"), &lists);
                let label = if filter.is_empty() { zone.clone() } else { format!("{zone} · {filter}") };
                (zone_id, zone, filter, label)
            };
            let (src_id, src_zone, src_filter, src_label) = side("source");
            let (dst_id, dst_zone, dst_filter, dst_label) = side("destination");

            json!({
                "name": p.get("name").cloned().unwrap_or(Value::Null),
                "action": p.pointer("/action/type").cloned().unwrap_or(Value::Null),
                "from": src_label,
                "to": dst_label,
                "log": if p.get("loggingEnabled").and_then(Value::as_bool).unwrap_or(false) { "on" } else { "off" },
                "enabled": p.get("enabled").cloned().unwrap_or(Value::Null),
                "origin": p.pointer("/metadata/origin").cloned().unwrap_or(Value::Null),
                "index": p.get("index").cloned().unwrap_or(Value::Null),
                "id": p.get("id").cloned().unwrap_or(Value::Null),
                // The normalized match, used to find exact duplicates. Two rules
                // sharing it accept or refuse exactly the same traffic.
                "match": format!("{src_id}|{src_filter}|{dst_id}|{dst_filter}|{}|{}",
                    p.pointer("/action/type").and_then(Value::as_str).unwrap_or(""),
                    p.pointer("/ipProtocolScope/ipVersion").and_then(Value::as_str).unwrap_or("")),
                "sourceZone": src_zone,
                "destinationZone": dst_zone,
                "sourceZoneId": src_id,
                "destinationZoneId": dst_id,
                "wideOpen": src_filter.is_empty() && dst_filter.is_empty(),
            })
        })
        .collect();

    render::heading("Firewall policies");
    render::list(&rows, render::POLICY_COLS);
    render::count(rows.len(), "policy");

    if render::is_json() {
        return Ok(());
    }
    report(&rows, &raw, &empty_zones, derived || all, all);
    Ok(())
}

/// Rule ordering is not analysed, and this says why rather than staying silent.
const ORDER_CAVEAT: &str = "rule order is not analysed: the API reports `index` as a bucket, \
     not a sequence, so which rule wins inside one cannot be established and no rule is \
     called shadowed";

fn report(
    rows: &[Value],
    raw: &[Value],
    empty_zones: &HashMap<String, String>,
    wide_set: bool,
    showing_system: bool,
) {
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();

    // Findings cover what the operator can act on. System rules are the default
    // zone matrix: most of them reference an empty zone or match everything by
    // design, and reporting that is noise rather than a finding.
    let owned: Vec<&Value> = rows
        .iter()
        .filter(|r| r["origin"].as_str() != Some("SYSTEM_DEFINED"))
        .collect();
    let rows: Vec<Value> = owned.into_iter().cloned().collect();
    let rows = &rows[..];

    if showing_system {
        ui::info(&format!(
            "{} system rule(s) shown but not assessed: they are the default zone matrix",
            raw.iter()
                .filter(|r| r.pointer("/metadata/origin").and_then(Value::as_str)
                    == Some("SYSTEM_DEFINED"))
                .count()
        ));
    }

    let disabled = rows.iter().filter(|r| r["enabled"] == json!(false)).count();
    if disabled > 0 {
        ui::info(&format!("{disabled} rule(s) present but disabled"));
    }

    let unlogged = rows.iter().filter(|r| r["log"] == json!("off")).count();
    if unlogged > 0 {
        ui::warning(&format!(
            "{unlogged} rule(s) with logging off: what they allow is never recorded, \
             and there is nothing to go back to afterwards"
        ));
    }

    // Exact duplicates, on the normalized match rather than on the name: two
    // rules can be named differently and still accept the same traffic.
    // Grouped by origin as well as by match: a zone-symmetric rule and the
    // return rule the console generates from it necessarily match the same
    // traffic, and calling that a duplicate blames the operator for the
    // console's own bookkeeping.
    let mut seen: HashMap<(String, String), Vec<String>> = HashMap::new();
    for r in rows {
        seen.entry((s(r, "match"), s(r, "origin")))
            .or_default()
            .push(s(r, "name"));
    }
    let dupes: Vec<&Vec<String>> = seen.values().filter(|v| v.len() > 1).collect();
    if !dupes.is_empty() {
        ui::warning(&format!(
            "{} set(s) of rules match identical traffic: {}",
            dupes.len(),
            dupes
                .iter()
                .map(|v| v.join(" = "))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }

    let dead: Vec<String> = rows
        .iter()
        .filter(|r| {
            empty_zones.contains_key(&s(r, "sourceZoneId"))
                || empty_zones.contains_key(&s(r, "destinationZoneId"))
        })
        .map(|r| s(r, "name"))
        .collect();
    if !dead.is_empty() {
        ui::warning(&format!(
            "{} rule(s) reference a zone holding no network, so nothing can match them: {}",
            dead.len(),
            capped(&dead)
        ));
    }

    let self_zone = rows
        .iter()
        .filter(|r| {
            !s(r, "sourceZoneId").is_empty() && s(r, "sourceZoneId") == s(r, "destinationZoneId")
        })
        .count();
    if self_zone > 0 {
        ui::info(&format!(
            "{self_zone} rule(s) have the same zone on both sides, which traffic inside a \
             zone usually does not need"
        ));
    }

    let wide = rows.iter().filter(|r| r["wideOpen"] == json!(true)).count();
    if wide > 0 {
        ui::info(&format!(
            "{wide} of {} rule(s) match any traffic between their zones: segmentation is \
             at zone granularity, which may be the intent",
            rows.len()
        ));
    }

    ui::info(ORDER_CAVEAT);
    if !wide_set {
        let hidden = raw.len() - rows.len();
        ui::info(&format!(
            "{hidden} generated and system rule(s) not shown, add --derived or --all"
        ));
    }
}

/// Join names for a one-line message, keeping it readable however many there are.
fn capped(names: &[String]) -> String {
    const MAX: usize = 6;
    if names.len() <= MAX {
        return names.join(", ");
    }
    format!(
        "{}, and {} more",
        names[..MAX].join(", "),
        names.len() - MAX
    )
}

/// Named port and address lists, so a rule shows real ports rather than a uuid.
async fn matching_lists(c: &Client, site: &str) -> HashMap<String, String> {
    let path = format!("/sites/{}/traffic-matching-lists", esc(site));
    let Ok(lists) = c.list(&path, &[], 0, None).await else {
        return HashMap::new();
    };

    lists
        .iter()
        .filter_map(|l| {
            let id = l.get("id")?.as_str()?.to_string();
            let name = l.get("name").and_then(Value::as_str).unwrap_or("list");
            let items: Vec<String> = l
                .get("items")?
                .as_array()?
                .iter()
                .filter_map(|i| i.get("value").map(scalar_text))
                .collect();
            Some((id, format!("{name} ({})", items.join(","))))
        })
        .collect()
}

/// One-line description of what a side of a rule matches, empty when it matches
/// everything.
fn describe_filter(filter: Option<&Value>, lists: &HashMap<String, String>) -> String {
    let Some(f) = filter else {
        return String::new();
    };

    if let Some(ips) = f
        .pointer("/ipAddressFilter/items")
        .and_then(Value::as_array)
    {
        let vals: Vec<String> = ips
            .iter()
            .filter_map(|i| i.get("value").map(scalar_text))
            .collect();
        if !vals.is_empty() {
            return vals.join(", ");
        }
    }
    if let Some(pf) = f.get("portFilter") {
        if let Some(id) = pf.get("trafficMatchingListId").and_then(Value::as_str) {
            return lists
                .get(id)
                .cloned()
                .unwrap_or_else(|| format!("list {id}"));
        }
        if let Some(ports) = pf.get("items").and_then(Value::as_array) {
            let vals: Vec<String> = ports
                .iter()
                .filter_map(|i| i.get("value").map(scalar_text))
                .collect();
            if !vals.is_empty() {
                return format!("ports {}", vals.join(","));
            }
        }
    }
    // A filter shape we do not decode yet: name it rather than claim "any".
    f.get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default()
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
