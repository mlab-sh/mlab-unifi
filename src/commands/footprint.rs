//! `footprint` — what this site looks like from the outside.
//!
//! Two halves. What the console knows about its own uplink and about how
//! reachable it is, which is entirely local. And what only an outside observer
//! can say about the public address, which needs `--allow-web`.
//!
//! The split matters here more than elsewhere, because a console behind another
//! router does not know its own public address at all. Reporting the private
//! WAN address as an external footprint would be exactly wrong.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

const IP_ENDPOINT: &str = "https://mlab.sh/api/v1/scan/ip";

#[derive(Args, Debug)]
pub struct FootprintArgs {
    /// Enrich the public address through mlab.sh: prefix, reverse name, abuse contact
    #[arg(long)]
    pub allow_web: bool,

    /// The public address to enrich, when the console sits behind another router
    #[arg(long, value_name = "IP")]
    pub public_ip: Option<String>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &FootprintArgs) -> Result<()> {
    unifi::local_only(c, "footprint")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    let wan = wan_health(c, &legacy).await;
    let sys = one_of(c, &legacy, "stat/sysinfo").await;
    let settings = settings_by_key(c, &legacy).await;
    let ddns = list_of(c, &legacy, "rest/dynamicdns").await;
    let forwards = list_of(c, &legacy, "rest/portforward").await;

    let wan_ip = text(&wan, "wan_ip");
    let private = is_private(&wan_ip);

    // The address to enrich: the WAN address when it is routable, otherwise the
    // one the operator supplies, because the console cannot know it.
    let target = a
        .public_ip
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| Some(wan_ip.clone()).filter(|ip| !ip.is_empty() && !private));

    let enriched = match (&target, a.allow_web) {
        (Some(ip), true) => lookup(ip).await,
        _ => None,
    };

    if render::is_json() {
        render::print_json(&json!({
            "uplink": uplink(&wan, private),
            "reachability": reachability(&sys, &settings),
            "published": {
                "portForwards": forwards.iter().filter(|f| flag(f, "enabled")).count(),
                "dynamicDns": ddns.len(),
            },
            "publicAddress": enriched,
        }));
        return Ok(());
    }

    render::heading("Uplink");
    render::pairs(&uplink_pairs(&wan, private));

    render::heading("How reachable this console is");
    render::pairs(&reachability_pairs(&sys, &settings));

    let active = forwards.iter().filter(|f| flag(f, "enabled")).count();
    ui::info(&format!(
        "{active} active port forward(s) publish a service inbound, listed by `network exposure`"
    ));
    for d in &ddns {
        ui::warning(&format!(
            "dynamic DNS publishes {} at {}: a permanent name pointing here",
            text(d, "host_name"),
            text(d, "service")
        ));
    }

    match (&enriched, &target, a.allow_web) {
        (Some(v), _, _) => {
            render::heading("The public address, seen from outside");
            render::one(v);
        }
        (None, Some(ip), true) => ui::warning(&format!("could not look {ip} up")),
        (None, Some(_), false) => {
            ui::info("add --allow-web to resolve the prefix, reverse name and abuse contact")
        }
        (None, None, _) => ui::info(
            "the console has no routable address of its own, so nothing here can describe \
             your public footprint; pass --public-ip with the address you know to enrich it",
        ),
    }

    if private {
        ui::info(&format!(
            "the WAN address {wan_ip} is private: this console sits behind another router, \
             and the operator and network number above come from the console's own outbound \
             checks rather than from that address"
        ));
    }
    Ok(())
}

// ---- the uplink -------------------------------------------------------------

fn uplink(wan: &Value, private: bool) -> Value {
    json!({
        "wanIp": text(wan, "wan_ip"),
        "wanIpScope": if private { "private" } else { "public" },
        "gateway": wan.get("gateways").and_then(|g| g.get(0)).cloned().unwrap_or(Value::Null),
        "isp": text(wan, "isp_name"),
        "organization": text(wan, "isp_organization"),
        "asn": wan.get("asn").cloned().unwrap_or(Value::Null),
        "nameservers": wan.get("nameservers").cloned().unwrap_or(Value::Null),
        "status": text(wan, "status"),
    })
}

fn uplink_pairs(wan: &Value, private: bool) -> Vec<(&'static str, String)> {
    let dns = wan
        .get("nameservers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    vec![
        (
            "address",
            format!(
                "{} ({})",
                text(wan, "wan_ip"),
                if private { "private" } else { "public" }
            ),
        ),
        (
            "gateway",
            wan.get("gateways")
                .and_then(|g| g.get(0))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        ("operator", text(wan, "isp_name")),
        (
            "network number",
            wan.get("asn").map(|a| format!("AS{a}")).unwrap_or_default(),
        ),
        (
            "resolvers",
            if dns.is_empty() {
                "none reported".into()
            } else {
                dns
            },
        ),
        ("link", text(wan, "status")),
    ]
}

// ---- how reachable the console is -------------------------------------------

fn reachability(sys: &Value, settings: &HashMap<String, Value>) -> Value {
    let mgmt = settings.get("mgmt").cloned().unwrap_or(Value::Null);
    json!({
        "cloudConsole": sys.get("is_cloud_console").cloned().unwrap_or(Value::Null),
        "identityProvider": flag(&mgmt, "unifi_idp_enabled"),
        "wifiman": flag(&mgmt, "wifiman_enabled"),
        "remoteVpn": settings.get("teleport").map(|t| flag(t, "enabled")).unwrap_or(false),
        "sshBindsEverywhere": flag(&mgmt, "x_ssh_bind_wildcard"),
        "httpsPort": sys.get("https_port").cloned().unwrap_or(Value::Null),
        "informPort": sys.get("inform_port").cloned().unwrap_or(Value::Null),
        "hostname": text(sys, "hostname"),
    })
}

fn reachability_pairs(
    sys: &Value,
    settings: &HashMap<String, Value>,
) -> Vec<(&'static str, String)> {
    let mgmt = settings.get("mgmt").cloned().unwrap_or(Value::Null);
    let yes_no = |b: bool| {
        if b {
            "yes".to_string()
        } else {
            "no".to_string()
        }
    };

    vec![
        (
            "hosted by the vendor",
            yes_no(
                sys.get("is_cloud_console")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        ("vendor sign-in", yes_no(flag(&mgmt, "unifi_idp_enabled"))),
        ("wifiman", yes_no(flag(&mgmt, "wifiman_enabled"))),
        (
            "remote vpn",
            yes_no(
                settings
                    .get("teleport")
                    .map(|t| flag(t, "enabled"))
                    .unwrap_or(false),
            ),
        ),
        (
            "ssh on every interface",
            yes_no(flag(&mgmt, "x_ssh_bind_wildcard")),
        ),
        (
            "management port",
            sys.get("https_port")
                .map(|p| p.to_string())
                .unwrap_or_default(),
        ),
    ]
}

// ---- the outside view -------------------------------------------------------

/// What an outside observer can say about an address. Only reached with
/// `--allow-web`, and it necessarily tells the service being asked which
/// address you are asking about.
async fn lookup(ip: &str) -> Option<Value> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("mlab-unifi/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;

    let v: Value = ui::spin(
        &format!("Looking up {ip}"),
        http.get(IP_ENDPOINT).query(&[("ip", ip)]).send(),
    )
    .await
    .ok()?
    .json()
    .await
    .ok()?;

    // No address in the reply means the service refused or rate-limited.
    v.get("ip")?;
    Some(json!({
        "address": v.get("ip").cloned().unwrap_or(Value::Null),
        "reverseName": v.get("rdns").cloned().unwrap_or(Value::Null),
        "autonomousSystem": v.get("as").cloned().unwrap_or(Value::Null),
        "operator": v.get("isp").cloned().unwrap_or(Value::Null),
        "organization": v.get("org").cloned().unwrap_or(Value::Null),
        "country": v.get("country").cloned().unwrap_or(Value::Null),
        "prefix": v.pointer("/rdap/cidr").cloned().unwrap_or(Value::Null),
        "abuseContact": v.pointer("/rdap/abuse_email").cloned().unwrap_or(Value::Null),
        "hosting": v.get("hosting").cloned().unwrap_or(Value::Null),
        "proxy": v.get("proxy").cloned().unwrap_or(Value::Null),
    }))
}

/// Addresses the internet does not route to.
fn is_private(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 {
        return false;
    }
    match (o[0], o[1]) {
        (10, _) | (127, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        (100, b) if (64..=127).contains(&b) => true,
        _ => false,
    }
}

// ---- fetches ----------------------------------------------------------------

async fn wan_health(c: &Client, legacy: &str) -> Value {
    ui::spin(
        "Reading the uplink",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/health", esc(legacy)),
            &[],
        ),
    )
    .await
    .unwrap_or_default()
    .into_iter()
    .find(|h| h.get("subsystem").and_then(Value::as_str) == Some("wan"))
    .unwrap_or(Value::Null)
}

async fn one_of(c: &Client, legacy: &str, path: &str) -> Value {
    list_of(c, legacy, path)
        .await
        .into_iter()
        .next()
        .unwrap_or(Value::Null)
}

async fn list_of(c: &Client, legacy: &str, path: &str) -> Vec<Value> {
    c.list_on(Surface::Legacy, &format!("/s/{}/{path}", esc(legacy)), &[])
        .await
        .unwrap_or_default()
}

async fn settings_by_key(c: &Client, legacy: &str) -> HashMap<String, Value> {
    list_of(c, legacy, "rest/setting")
        .await
        .into_iter()
        .filter_map(|s| Some((s.get("key")?.as_str()?.to_string(), s)))
        .collect()
}

fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unroutable_uplink_is_recognised() {
        // The case that matters: a console behind another router reports a
        // private WAN address, and calling it a public footprint is wrong.
        assert!(is_private("192.168.1.61"));
        assert!(is_private("10.0.0.1"));
        assert!(is_private("172.20.5.4"));
        assert!(
            is_private("100.64.0.1"),
            "carrier-grade NAT is not routable either"
        );
        assert!(!is_private("172.32.0.1"), "just outside the block");
        assert!(!is_private("81.250.4.1"));
        assert!(!is_private("not an address"));
    }

    #[test]
    fn the_uplink_block_says_which_kind_of_address_it_is() {
        let wan = json!({"wan_ip": "192.168.1.61", "isp_name": "Example", "asn": 12322});
        let v = uplink(&wan, true);
        assert_eq!(v["wanIpScope"], json!("private"));
        assert_eq!(
            v["asn"],
            json!(12322),
            "the network number is known even so"
        );
    }
}
