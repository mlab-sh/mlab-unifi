//! `posture` — what the site's own settings say it is defending, and with what.
//!
//! The whole command reads one legacy route, `rest/setting`, and turns 38
//! configuration sections into checks.
//!
//! Two states are deliberately kept apart, because conflating them is how a
//! posture report becomes noise. A control that is **off** is usually a
//! decision: nobody runs TLS inspection or a NetFlow collector by accident. A
//! control that **looks on and does nothing** is a different thing entirely,
//! and it is the only kind this command raises its voice about.

use std::collections::HashMap;

use anyhow::Result;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

/// Field names that hold an actual secret.
///
/// Deliberately an explicit list rather than a substring rule: `key` is the
/// name of a settings section, and matching on it flags all 38 of them.
const SECRET_FIELDS: [&str; 14] = [
    "x_ssh_password",
    "x_ssh_sha512passwd",
    "x_passphrase",
    "x_api_token",
    "x_mgmt_key",
    "x_private_key",
    "x_mesh_psk",
    "x_element_psk",
    "x_pregenerated_dh_key",
    "x_iapp_key",
    "x_authkey",
    "x_inform_authkey",
    "syslog_key",
    "x_vwirekey",
];

/// One thing looked at, and what was found.
struct Check {
    area: &'static str,
    name: &'static str,
    state: &'static str,
    detail: String,
    /// True when the setting misleads: it reads as protection but is not one.
    attention: bool,
}

impl Check {
    fn row(&self) -> Value {
        json!({
            "area": self.area,
            "check": self.name,
            "state": self.state,
            "detail": self.detail,
            "attention": self.attention,
        })
    }
}

fn ok(area: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        area,
        name,
        state: "ok",
        detail: detail.into(),
        attention: false,
    }
}

fn off(area: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        area,
        name,
        state: "off",
        detail: detail.into(),
        attention: false,
    }
}

/// Present, but not doing what its name suggests.
fn weak(area: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        area,
        name,
        state: "weak",
        detail: detail.into(),
        attention: true,
    }
}

/// The section was not returned, so nothing is claimed either way.
fn unknown(area: &'static str, name: &'static str) -> Check {
    Check {
        area,
        name,
        state: "unknown",
        detail: "the console did not report this section".into(),
        attention: false,
    }
}

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    unifi::local_only(c, "posture")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    let raw = ui::spin(
        "Reading site settings",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/rest/setting", esc(&legacy)),
            &[],
        ),
    )
    .await?;

    let by_key: HashMap<String, &Value> = raw
        .iter()
        .filter_map(|s| Some((s.get("key")?.as_str()?.to_string(), s)))
        .collect();

    let mut checks = Vec::new();
    checks.extend(threats(&by_key));
    checks.extend(inspection(&by_key));
    checks.extend(access(&by_key));
    checks.extend(logging(&by_key));
    checks.extend(upkeep(&by_key));

    let secrets = secret_count(&raw);
    checks.push(if secrets > 0 {
        weak(
            "secrets",
            "readable by this API key",
            format!("{secrets} field(s) come back in clear text"),
        )
    } else {
        ok("secrets", "readable by this API key", "none")
    });

    let rows: Vec<Value> = checks.iter().map(Check::row).collect();

    render::heading("Security posture");
    render::list(&rows, render::POSTURE_CHECK_COLS);
    render::count(rows.len(), "check");

    if render::is_json() {
        return Ok(());
    }

    let flagged: Vec<&Check> = checks.iter().filter(|c| c.attention).collect();
    if flagged.is_empty() {
        ui::success("nothing here reads as protection without being one");
    }
    for c in &flagged {
        ui::warning(&format!("{}: {}", c.name, c.detail));
    }

    let inactive = checks.iter().filter(|c| c.state == "off").count();
    if inactive > 0 {
        ui::info(&format!(
            "{inactive} control(s) simply off, which is usually a decision rather than an \
             oversight and is listed without comment"
        ));
    }
    let blind = checks.iter().filter(|c| c.state == "unknown").count();
    if blind > 0 {
        ui::info(&format!(
            "{blind} check(s) could not be evaluated: a missing section is not a pass"
        ));
    }
    Ok(())
}

// ---- areas ------------------------------------------------------------------

fn threats(s: &HashMap<String, &Value>) -> Vec<Check> {
    let mut out = Vec::new();

    match s.get("ips") {
        None => out.push(unknown("threats", "intrusion prevention")),
        Some(ips) => {
            let categories = ips
                .get("enabled_categories")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let filtering = text(ips, "advanced_filtering_preference");

            out.push(if categories == 0 {
                weak(
                    "threats",
                    "intrusion prevention",
                    "no signature category is selected, so nothing is inspected",
                )
            } else {
                ok(
                    "threats",
                    "intrusion prevention",
                    format!("{categories} categor(y|ies) armed"),
                )
            });

            out.push(match flag(ips, "ad_blocking_enabled") {
                true => ok("threats", "ad blocking", ""),
                false => off("threats", "ad blocking", ""),
            });

            // A filter list attached to a network but set to "none" filters
            // nothing; it reads as configured because the entry exists.
            let filters = ips
                .get("dns_filters")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let live = filters
                .iter()
                .filter(|f| text(f, "filter") != "none")
                .count();
            out.push(if filters.is_empty() {
                off("threats", "DNS filtering", "")
            } else if live == 0 {
                weak(
                    "threats",
                    "DNS filtering",
                    format!("{} network(s) carry a filter set to none", filters.len()),
                )
            } else {
                ok(
                    "threats",
                    "DNS filtering",
                    format!("{live} network(s) filtered"),
                )
            });

            if filtering != "disabled" && !filtering.is_empty() {
                out.push(ok("threats", "advanced filtering", filtering));
            } else {
                out.push(off("threats", "advanced filtering", ""));
            }
        }
    }

    out.push(match s.get("usg_geo") {
        None => unknown("threats", "geo IP filtering"),
        Some(g) => {
            if g.pointer("/ip_filtering/enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                ok(
                    "threats",
                    "geo IP filtering",
                    text(&g["ip_filtering"], "action"),
                )
            } else {
                off("threats", "geo IP filtering", "")
            }
        }
    });
    out
}

fn inspection(s: &HashMap<String, &Value>) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(match s.get("dpi") {
        None => unknown("inspection", "deep packet inspection"),
        Some(d) if flag(d, "enabled") => ok(
            "inspection",
            "deep packet inspection",
            if flag(d, "fingerprintingEnabled") {
                "with fingerprinting"
            } else {
                ""
            },
        ),
        Some(_) => off("inspection", "deep packet inspection", ""),
    });

    out.push(match s.get("ssl_inspection") {
        None => unknown("inspection", "TLS inspection"),
        Some(v) if text(v, "state") != "off" => {
            ok("inspection", "TLS inspection", text(v, "state"))
        }
        Some(_) => off("inspection", "TLS inspection", ""),
    });

    out.push(match s.get("doh") {
        None => unknown("inspection", "DNS over HTTPS"),
        Some(v) => {
            let servers = v
                .get("server_names")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if text(v, "state") == "off" {
                off("inspection", "DNS over HTTPS", "")
            } else {
                ok("inspection", "DNS over HTTPS", servers)
            }
        }
    });
    out
}

fn access(s: &HashMap<String, &Value>) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(match s.get("mgmt") {
        None => unknown("access", "device SSH"),
        Some(m) if !flag(m, "x_ssh_enabled") => off("access", "device SSH", ""),
        Some(m) => {
            let keys = m
                .get("x_ssh_keys")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if keys == 0 {
                // And the password itself is readable through this same API.
                weak(
                    "access",
                    "device SSH",
                    "enabled with no key, so password only",
                )
            } else {
                ok("access", "device SSH", format!("{keys} key(s) installed"))
            }
        }
    });

    out.push(match s.get("guest_access") {
        None => unknown("access", "guest portal"),
        Some(g) if !flag(g, "portal_enabled") => off("access", "guest portal", ""),
        Some(g) if text(g, "auth") == "none" => weak(
            "access",
            "guest portal",
            "open, anyone reaching it is admitted",
        ),
        Some(g) => ok("access", "guest portal", text(g, "auth")),
    });

    out.push(match s.get("teleport") {
        None => unknown("access", "remote VPN"),
        Some(t) if flag(t, "enabled") => ok(
            "access",
            "remote VPN",
            format!("on, {}", text(t, "subnet_cidr")),
        ),
        Some(_) => off("access", "remote VPN", ""),
    });

    out.push(match s.get("global_switch") {
        None => unknown("access", "802.1X on switch ports"),
        Some(g) if flag(g, "dot1x_portctrl_enabled") => ok("access", "802.1X on switch ports", ""),
        Some(_) => off(
            "access",
            "802.1X on switch ports",
            "a device plugged into a port joins without authenticating",
        ),
    });

    out.push(match s.get("usg") {
        None => unknown("access", "UPnP on the gateway"),
        Some(u) if flag(u, "upnp_enabled") => weak(
            "access",
            "UPnP on the gateway",
            "a host can publish its own inbound port",
        ),
        Some(_) => ok("access", "UPnP on the gateway", "off"),
    });

    out.push(match s.get("global_network") {
        None => unknown("access", "default posture between zones"),
        Some(g) => {
            let p = text(g, "default_security_posture");
            if p.contains("ALLOW") {
                weak(
                    "access",
                    "default posture between zones",
                    format!("{p}, so a zone pair with no rule is permitted"),
                )
            } else {
                ok("access", "default posture between zones", p)
            }
        }
    });
    out
}

fn logging(s: &HashMap<String, &Value>) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(match s.get("rsyslogd") {
        None => unknown("logging", "syslog"),
        Some(r) if !flag(r, "enabled") => off("logging", "syslog", ""),
        Some(r) => {
            let remote = !text(r, "ip").is_empty();
            if remote {
                ok(
                    "logging",
                    "syslog",
                    format!("forwarded to {}", text(r, "ip")),
                )
            } else {
                // Logs that never leave the console are lost with the console,
                // which is the case an investigation cares about.
                weak(
                    "logging",
                    "syslog",
                    "kept on the console only, nothing is forwarded",
                )
            }
        }
    });

    out.push(match s.get("netflow") {
        None => unknown("logging", "flow export"),
        Some(n) if flag(n, "enabled") => ok(
            "logging",
            "flow export",
            format!("to port {}", n.get("port").unwrap_or(&Value::Null)),
        ),
        Some(_) => off("logging", "flow export", ""),
    });

    out.push(match s.get("super_smtp") {
        None => unknown("logging", "mail alerting"),
        Some(m) if flag(m, "enabled") => ok("logging", "mail alerting", text(m, "host")),
        Some(_) => off("logging", "mail alerting", "no alert leaves the console"),
    });

    out.push(match s.get("super_mgmt") {
        None => unknown("logging", "statistics retention"),
        Some(m) => {
            let hours = |k: &str| m.get(k).and_then(Value::as_i64).unwrap_or(0);
            ok(
                "logging",
                "statistics retention",
                format!(
                    "{}h at 5 minutes, {}d hourly, {}d daily",
                    hours("data_retention_time_in_hours_for_5minutes_scale"),
                    hours("data_retention_time_in_hours_for_hourly_scale") / 24,
                    hours("data_retention_time_in_hours_for_daily_scale") / 24
                ),
            )
        }
    });
    out
}

fn upkeep(s: &HashMap<String, &Value>) -> Vec<Check> {
    vec![
        match s.get("super_mgmt") {
            None => unknown("upkeep", "automatic backup"),
            Some(m) if flag(m, "autobackup_enabled") => ok("upkeep", "automatic backup", ""),
            Some(_) => off("upkeep", "automatic backup", ""),
        },
        match s.get("mgmt") {
            None => unknown("upkeep", "automatic firmware upgrade"),
            Some(m) if flag(m, "auto_upgrade") => ok("upkeep", "automatic firmware upgrade", ""),
            Some(_) => off("upkeep", "automatic firmware upgrade", ""),
        },
        match s.get("super_mgmt") {
            None => unknown("upkeep", "usage analytics"),
            Some(m) if flag(m, "enable_analytics") => ok(
                "upkeep",
                "usage analytics",
                "on, telemetry leaves the console",
            ),
            Some(_) => ok("upkeep", "usage analytics", "off"),
        },
    ]
}

// ---- helpers ----------------------------------------------------------------

fn secret_count(raw: &[Value]) -> usize {
    raw.iter()
        .flat_map(|s| s.as_object().into_iter().flatten())
        .filter(|(k, v)| {
            SECRET_FIELDS.contains(&k.as_str()) && v.as_str().is_some_and(|s| !s.is_empty())
        })
        .count()
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
    fn a_section_name_is_not_a_secret() {
        // Every settings section carries `key` as its own name; a substring
        // rule on "key" reports all 38 of them as credentials.
        let sections = vec![
            json!({"key": "ips", "utm_token": "x"}),
            json!({"key": "mgmt", "x_ssh_password": "hunter2", "x_ssh_keys": []}),
        ];
        assert_eq!(secret_count(&sections), 1, "only the password counts");
    }

    #[test]
    fn an_empty_secret_field_is_not_an_exposure() {
        assert_eq!(secret_count(&[json!({"x_passphrase": ""})]), 0);
    }

    #[test]
    fn prevention_with_no_category_reads_as_weak_not_as_on() {
        let raw = json!({"enabled": true, "enabled_categories": []});
        let map: HashMap<String, &Value> = [("ips".to_string(), &raw)].into_iter().collect();
        let ips = threats(&map)
            .into_iter()
            .find(|c| c.name == "intrusion prevention")
            .unwrap();
        assert_eq!(ips.state, "weak");
        assert!(
            ips.attention,
            "a control that inspects nothing must be raised"
        );
    }

    #[test]
    fn a_missing_section_is_never_a_pass() {
        let empty: HashMap<String, &Value> = HashMap::new();
        let mut all = threats(&empty);
        all.extend(inspection(&empty));
        all.extend(access(&empty));
        all.extend(logging(&empty));
        assert!(all.iter().all(|c| c.state == "unknown"));
        assert!(
            all.iter().all(|c| !c.attention),
            "absence is not a finding either"
        );
    }
}
