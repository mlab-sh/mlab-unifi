//! `blast` — what a compromised client would reach.
//!
//! Two things had to be true for this to be sound, and both were checked
//! against the console rather than assumed.
//!
//! **Order is determined inside a zone pair.** Rule indices collide across the
//! rule set as a whole, which is why [`crate::commands::network`] refuses to
//! call anything shadowed. Within one source-destination pair they never do
//! (0 collisions in 255 pairs), and a packet is only ever evaluated against the
//! rules for its own pair. So the verdict for a pair *is* computable.
//!
//! **Only some rules decide it.** `Block Invalid Traffic` looks like a blanket
//! block and is not: it matches the `INVALID` connection state alone. Reading a
//! pair's verdict off the first rule regardless would report most of the
//! network as unreachable. Only rules that apply to every connection state
//! count, and that field exists on the v2 surface only, which is why the matrix
//! is built there.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

#[derive(Args, Debug)]
pub struct BlastArgs {
    /// A client, by MAC address or by name
    #[arg(value_name = "MAC|NAME")]
    pub from: Option<String>,

    /// Start from a zone instead of a client
    #[arg(long, value_name = "ZONE")]
    pub zone: Option<String>,
}

/// What one zone pair permits.
#[derive(Clone, Copy, PartialEq)]
enum Verdict {
    /// Any traffic is accepted.
    Open,
    /// Only what a specific rule names: certain addresses or ports.
    Partial,
    Blocked,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Open => "everything",
            Verdict::Partial => "specific hosts or ports",
            Verdict::Blocked => "nothing",
        }
    }
}

pub async fn run(c: &Client, ctx: &Ctx, a: &BlastArgs) -> Result<()> {
    unifi::local_only(c, "blast")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    let networks = fetch(c, &legacy, "rest/networkconf").await?;
    let users = fetch(c, &legacy, "rest/user").await?;
    let zones = ui::spin(
        "Listing firewall zones",
        c.list(
            &format!("/sites/{}/firewall/zones", esc(&site)),
            &[],
            0,
            None,
        ),
    )
    .await?;
    let policies = ui::spin(
        "Reading firewall policies",
        c.list_on(
            Surface::V2,
            &format!("/site/{}/firewall-policies", esc(&legacy)),
            &[],
        ),
    )
    .await
    .unwrap_or_default();

    let names = zone_names(&zones, &networks);
    let (start_zone, origin) = start(a, &users, &networks, &names)?;

    // Where each zone's hosts live, so a verdict can be turned into a count.
    let mut hosts: HashMap<String, usize> = HashMap::new();
    let net_zone: HashMap<String, String> = networks
        .iter()
        .filter_map(|n| {
            Some((
                n.get("_id")?.as_str()?.to_string(),
                n.get("firewall_zone_id")?.as_str()?.to_string(),
            ))
        })
        .collect();
    for u in &users {
        if let Some(z) = u
            .get("last_connection_network_id")
            .and_then(Value::as_str)
            .and_then(|n| net_zone.get(n))
        {
            *hosts.entry(z.clone()).or_default() += 1;
        }
    }

    let matrix = build_matrix(&policies);
    let mut rows: Vec<Value> = Vec::new();

    for (zone_id, zone_name) in &names {
        if zone_id == &start_zone {
            continue;
        }
        let verdict = matrix
            .get(&(start_zone.clone(), zone_id.clone()))
            .copied()
            .unwrap_or(Verdict::Blocked);
        if verdict == Verdict::Blocked {
            continue;
        }
        let nets: Vec<String> = networks
            .iter()
            .filter(|n| n.get("firewall_zone_id").and_then(Value::as_str) == Some(zone_id))
            .filter_map(|n| n.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();

        rows.push(json!({
            "zone": zone_name,
            "reaches": verdict.label(),
            "networks": nets,
            "hosts": hosts.get(zone_id).copied().unwrap_or(0),
        }));
    }
    rows.sort_by_key(|r| {
        (
            r["reaches"] != json!("everything"),
            r["zone"].as_str().unwrap_or("").to_string(),
        )
    });

    render::heading(&format!("What {origin} reaches"));
    render::list(&rows, render::BLAST_COLS);
    render::count(rows.len(), "zone");

    if render::is_json() {
        return Ok(());
    }

    let open = rows
        .iter()
        .filter(|r| r["reaches"] == json!("everything"))
        .count();
    let total: u64 = rows.iter().filter_map(|r| r["hosts"].as_u64()).sum();
    ui::info(&format!(
        "starting from {}, {} zone(s) are wide open and {total} known host(s) sit in reach",
        names.get(&start_zone).cloned().unwrap_or_default(),
        open
    ));
    ui::info(
        "this counts what the rules permit between zones, not what a service on the other \
         side actually exposes: a reachable host with nothing listening is reachable and \
         harmless",
    );
    Ok(())
}

/// The verdict for every ordered zone pair.
///
/// Only rules that apply to every connection state decide a pair. A rule
/// carrying a source or destination filter narrows the traffic rather than
/// settling the pair, so it downgrades an otherwise blocked pair to partial
/// instead of opening it.
fn build_matrix(policies: &[Value]) -> HashMap<(String, String), Verdict> {
    let mut by_pair: HashMap<(String, String), Vec<&Value>> = HashMap::new();
    for p in policies {
        if !p.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let src = zone_of(p, "source");
        let dst = zone_of(p, "destination");
        if let (Some(s), Some(d)) = (src, dst) {
            by_pair.entry((s, d)).or_default().push(p);
        }
    }

    by_pair
        .into_iter()
        .map(|(pair, mut rules)| {
            rules.sort_by_key(|p| p.get("index").and_then(Value::as_i64).unwrap_or(i64::MAX));

            let mut verdict = Verdict::Blocked;
            let mut partial = false;
            for p in rules {
                let all_states =
                    p.get("connection_state_type").and_then(Value::as_str) == Some("ALL");
                let allow = p.get("action").and_then(Value::as_str) == Some("ALLOW");
                let narrowed = is_narrowed(p);

                if narrowed {
                    // Names specific hosts or ports: some traffic gets through
                    // even where the pair as a whole is closed.
                    partial |= allow;
                    continue;
                }
                if !all_states {
                    continue;
                }
                verdict = if allow {
                    Verdict::Open
                } else {
                    Verdict::Blocked
                };
                break;
            }

            let verdict = match (verdict, partial) {
                (Verdict::Blocked, true) => Verdict::Partial,
                (v, _) => v,
            };
            (pair, verdict)
        })
        .collect()
}

/// Whether a rule matches only part of the traffic between its zones.
fn is_narrowed(p: &Value) -> bool {
    ["source", "destination"].iter().any(|side| {
        p.get(side).is_some_and(|s| {
            s.get("matching_target")
                .and_then(Value::as_str)
                .unwrap_or("ANY")
                != "ANY"
                || s.get("port_matching_type")
                    .and_then(Value::as_str)
                    .unwrap_or("ANY")
                    != "ANY"
        })
    }) || p.get("protocol").and_then(Value::as_str).unwrap_or("all") != "all"
}

fn zone_of(p: &Value, side: &str) -> Option<String> {
    p.get(side)?.get("zone_id")?.as_str().map(str::to_string)
}

/// Zone identifiers as the policies use them, mapped to readable names.
///
/// The two surfaces number zones differently and share no identifier, so the
/// bridge runs through the networks: a network carries the documented UUID on
/// one side and the internal zone id on the other. Only zones holding no
/// network stay unnamed, and those have no host to reach anyway.
fn zone_names(zones: &[Value], networks: &[Value]) -> HashMap<String, String> {
    let uuid_to_internal: HashMap<String, String> = networks
        .iter()
        .filter_map(|n| {
            Some((
                n.get("external_id")?.as_str()?.to_string(),
                n.get("firewall_zone_id")?.as_str()?.to_string(),
            ))
        })
        .collect();

    let mut out = HashMap::new();
    for z in zones {
        let Some(name) = z.get("name").and_then(Value::as_str) else {
            continue;
        };
        for nid in z
            .get("networkIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(internal) = nid.as_str().and_then(|u| uuid_to_internal.get(u)) {
                out.entry(internal.clone())
                    .or_insert_with(|| name.to_string());
            }
        }
    }
    out
}

/// The zone to start from, and how to describe it in the heading.
fn start(
    a: &BlastArgs,
    users: &[Value],
    networks: &[Value],
    names: &HashMap<String, String>,
) -> Result<(String, String)> {
    if let Some(z) = &a.zone {
        let found = names
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(z))
            .map(|(id, n)| (id.clone(), format!("zone {n}")));
        return found.with_context(|| {
            format!(
                "no zone named {z:?} holds a network (known: {})",
                listing(names)
            )
        });
    }

    let Some(want) = &a.from else {
        bail!("give a client by MAC or name, or a zone with --zone");
    };
    let needle = want.to_lowercase();

    let client = users
        .iter()
        .find(|u| {
            let f = |k: &str| {
                u.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase()
            };
            f("mac") == needle || f("name") == needle || f("hostname") == needle
        })
        .with_context(|| format!("no client known as {want:?}"))?;

    let net_id = client
        .get("last_connection_network_id")
        .and_then(Value::as_str)
        .context("that client has never been seen on a network")?;
    let zone = networks
        .iter()
        .find(|n| n.get("_id").and_then(Value::as_str) == Some(net_id))
        .and_then(|n| n.get("firewall_zone_id").and_then(Value::as_str))
        .context("that client's network is in no firewall zone")?;

    let label = client
        .get("name")
        .or_else(|| client.get("hostname"))
        .and_then(Value::as_str)
        .unwrap_or(want);
    let net = client
        .get("last_connection_network_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    Ok((zone.to_string(), format!("{label} on {net}")))
}

fn listing(names: &HashMap<String, String>) -> String {
    let mut v: Vec<&String> = names.values().collect();
    v.sort();
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
}

async fn fetch(c: &Client, legacy: &str, path: &str) -> Result<Vec<Value>> {
    c.list_on(Surface::Legacy, &format!("/s/{}/{path}", esc(legacy)), &[])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(src: &str, dst: &str, action: &str, index: i64, state: &str) -> Value {
        json!({
            "enabled": true, "index": index, "action": action,
            "connection_state_type": state, "protocol": "all",
            "source": {"zone_id": src, "matching_target": "ANY", "port_matching_type": "ANY"},
            "destination": {"zone_id": dst, "matching_target": "ANY", "port_matching_type": "ANY"}
        })
    }

    #[test]
    fn a_stateful_block_does_not_close_a_pair() {
        // The trap this command exists to avoid: "Block Invalid Traffic" sorts
        // first and is a BLOCK, but only for one connection state. Reading the
        // pair off it would report the network as unreachable.
        let m = build_matrix(&[
            rule("a", "b", "BLOCK", 30_000, "CUSTOM"),
            rule("a", "b", "ALLOW", 2_147_483_647, "ALL"),
        ]);
        assert!(matches!(m[&("a".into(), "b".into())], Verdict::Open));
    }

    #[test]
    fn the_lowest_index_that_applies_to_every_state_decides() {
        let m = build_matrix(&[
            rule("a", "b", "BLOCK", 100, "ALL"),
            rule("a", "b", "ALLOW", 200, "ALL"),
        ]);
        assert!(matches!(m[&("a".into(), "b".into())], Verdict::Blocked));
    }

    #[test]
    fn a_narrowed_allow_opens_part_of_a_closed_pair() {
        let mut narrow = rule("a", "b", "ALLOW", 10, "ALL");
        narrow["destination"]["matching_target"] = json!("IP");
        let m = build_matrix(&[narrow, rule("a", "b", "BLOCK", 2_147_483_647, "ALL")]);
        assert!(matches!(m[&("a".into(), "b".into())], Verdict::Partial));
    }

    #[test]
    fn a_disabled_rule_decides_nothing() {
        let mut off = rule("a", "b", "ALLOW", 10, "ALL");
        off["enabled"] = json!(false);
        let m = build_matrix(&[off, rule("a", "b", "BLOCK", 20, "ALL")]);
        assert!(matches!(m[&("a".into(), "b".into())], Verdict::Blocked));
    }

    #[test]
    fn a_pair_with_no_rule_at_all_is_absent_rather_than_open() {
        let m = build_matrix(&[rule("a", "b", "ALLOW", 10, "ALL")]);
        assert!(!m.contains_key(&("a".into(), "c".into())));
    }
}
