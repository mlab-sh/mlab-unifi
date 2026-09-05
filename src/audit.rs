//! The graded checks, as pure functions over already-fetched data.
//!
//! Kept apart from the command that feeds them so every rule here is testable
//! against a fixture with no console in the loop, which is the only way a
//! security check earns any trust.
//!
//! Two rules govern what may appear:
//!
//! * **A severity is about what it costs, not how it looks.** A control that is
//!   simply switched off is usually a decision and stays out; a control that
//!   reads as protection without being one belongs here.
//! * **A check that could not run produces nothing.** Never a pass. The command
//!   reports how many were skipped so an incomplete audit cannot pass for a
//!   clean one.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::enrich::firmware;
use crate::unifi::secrets::SECRET_FIELDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub area: &'static str,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

fn finding(
    severity: Severity,
    area: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    fix: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        area,
        title: title.into(),
        detail: detail.into(),
        fix: fix.into(),
    }
}

/// Everything the checks read. A missing piece means the checks that need it
/// are skipped, and counted as skipped.
#[derive(Default)]
pub struct Input {
    pub settings: HashMap<String, Value>,
    pub wlans: Vec<Value>,
    pub forwards: Vec<Value>,
    /// Collected for the segmentation checks that will need it; nothing reads
    /// it yet, and an unused field is cheaper than a second collection pass.
    #[allow(dead_code)]
    pub networks: Vec<Value>,
    pub zones: Vec<Value>,
    pub policies: Vec<Value>,
    pub devices: Vec<Value>,
}

/// Every finding, worst first.
pub fn run(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(credentials(i));
    out.extend(wireless(i));
    out.extend(segmentation(i));
    out.extend(exposure(i));
    out.extend(detection(i));
    out.extend(inventory(i));
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.area.cmp(b.area)));
    out
}

/// How many checks had no data to run against.
pub fn skipped(i: &Input) -> Vec<&'static str> {
    let mut out = Vec::new();
    if i.settings.is_empty() {
        out.push("site settings");
    }
    if i.wlans.is_empty() {
        out.push("wireless configuration");
    }
    if i.policies.is_empty() || i.zones.is_empty() {
        out.push("firewall policies");
    }
    if i.devices.is_empty() {
        out.push("device firmware");
    }
    out
}

// ---- credentials ------------------------------------------------------------

fn credentials(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(mgmt) = i.settings.get("mgmt") else {
        return out;
    };

    let keys = mgmt
        .get("x_ssh_keys")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let password_readable = mgmt
        .get("x_ssh_password")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());

    if flag(mgmt, "x_ssh_enabled") && keys == 0 {
        // The two facts are ordinary on their own and severe together: the only
        // factor is a password, and the same key that read this configuration
        // read the password itself.
        let severity = if password_readable {
            Severity::Critical
        } else {
            Severity::Medium
        };
        out.push(finding(
            severity,
            "credentials",
            "device SSH accepts a password and no key",
            if password_readable {
                "the password is returned in clear text by the same API key that reads this \
                 configuration, so holding the key is holding root on every device"
            } else {
                "a password is the only factor protecting shell access to every device"
            },
            "install an SSH key and disable password authentication, or turn device SSH off",
        ));
    }

    let exposed = i
        .settings
        .values()
        .flat_map(|s| s.as_object().into_iter().flatten())
        .filter(|(k, v)| {
            SECRET_FIELDS.contains(&k.as_str()) && v.as_str().is_some_and(|s| !s.is_empty())
        })
        .count();
    if exposed > 0 {
        out.push(finding(
            Severity::High,
            "credentials",
            "the API key reads secrets in clear text",
            format!("{exposed} field(s) come back readable, including keys and passphrases"),
            "treat the API key as an administrator credential: store and rotate it as one, \
             and never give it to anything that only needs an inventory",
        ));
    }
    out
}

// ---- wireless ---------------------------------------------------------------

fn wireless(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &i.wlans {
        let name = text(w, "name");
        let pmf = text(w, "pmf_mode");
        if pmf != "required" {
            out.push(finding(
                Severity::High,
                "wireless",
                format!("{name}: management frames are unprotected"),
                format!(
                    "protected management frames are {}, which is what lets a deauthentication \
                     burst throw clients off the network",
                    if pmf.is_empty() {
                        "unset"
                    } else {
                        pmf.as_str()
                    }
                ),
                "set protected management frames to required, and leave WPA3 transition mode \
                 so no client falls back past it",
            ));
        }
        if flag(w, "wpa3_transition") {
            out.push(finding(
                Severity::Medium,
                "wireless",
                format!("{name}: WPA3 is optional in practice"),
                "transition mode lets a client negotiate WPA2, so none of WPA3's guarantees \
                 hold for any client that asks not to",
                "move to WPA3 only once every client supports it",
            ));
        }
        let psk = w
            .get("x_passphrase")
            .and_then(Value::as_str)
            .map(|s| s.chars().count())
            .unwrap_or(0);
        if psk > 0 && psk < 12 {
            out.push(finding(
                Severity::Medium,
                "wireless",
                format!("{name}: the pre-shared key is short"),
                format!(
                    "{psk} characters, which is within reach of an offline attack once a \
                     handshake is captured"
                ),
                "lengthen it, or move to per-device keys so one compromise does not hand over \
                 the whole network",
            ));
        }
        if !flag(w, "private_preshared_keys_enabled") && psk > 0 {
            out.push(finding(
                Severity::Low,
                "wireless",
                format!("{name}: one key for every device"),
                "rotating it means reprovisioning everything, which is why it never gets \
                 rotated",
                "enable per-device pre-shared keys",
            ));
        }
    }
    out
}

// ---- segmentation -----------------------------------------------------------

fn segmentation(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(g) = i.settings.get("global_network") {
        let posture = text(g, "default_security_posture");
        if posture.contains("ALLOW") {
            out.push(finding(
                Severity::High,
                "segmentation",
                "zones permit each other by default",
                format!(
                    "the default posture is {posture}, so the rule set is a list of \
                     permissions on top of a default that already permits"
                ),
                "set the default posture to deny and let the rules grant what is needed",
            ));
        }
    }

    if let Some(g) = i.settings.get("global_switch") {
        if !flag(g, "dot1x_portctrl_enabled") {
            out.push(finding(
                Severity::Medium,
                "segmentation",
                "a switch port authenticates nobody",
                "802.1X is off, so anything plugged into a port joins the network it is \
                 patched to",
                "enable 802.1X on the ports that are physically reachable",
            ));
        }
    }

    // A zone with no network can never match, so a rule pointing at one does
    // nothing. The rule still expresses an intent, and that intent is not in
    // force: whatever it meant to restrict is decided by some other rule.
    let empty: HashSet<String> = i
        .zones
        .iter()
        .filter(|z| {
            z.get("networkIds")
                .and_then(Value::as_array)
                .is_some_and(|a| a.is_empty())
        })
        .filter_map(|z| z.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();

    let dead: Vec<String> = i
        .policies
        .iter()
        .filter(|p| p.pointer("/metadata/origin").and_then(Value::as_str) == Some("USER_DEFINED"))
        .filter(|p| {
            ["/source/zoneId", "/destination/zoneId"].iter().any(|ptr| {
                p.pointer(ptr)
                    .and_then(Value::as_str)
                    .is_some_and(|z| empty.contains(z))
            })
        })
        .map(|p| text(p, "name"))
        .collect();

    if !dead.is_empty() {
        out.push(finding(
            Severity::High,
            "segmentation",
            "a rule you wrote matches nothing",
            format!(
                "{} rule(s) point at a zone holding no network, so the restriction they \
                 express is not in force and the traffic is decided elsewhere: {}",
                dead.len(),
                dead.join(", ")
            ),
            "move the network into the zone the rule names, or rewrite the rule against the \
             zone the network is actually in",
        ));
    }

    let user: Vec<&Value> = i
        .policies
        .iter()
        .filter(|p| p.pointer("/metadata/origin").and_then(Value::as_str) == Some("USER_DEFINED"))
        .collect();
    let wide = user
        .iter()
        .filter(|p| {
            p.pointer("/source/trafficFilter").is_none()
                && p.pointer("/destination/trafficFilter").is_none()
        })
        .count();
    if wide > 0 && !user.is_empty() {
        out.push(finding(
            Severity::Medium,
            "segmentation",
            "most rules open a whole zone to another",
            format!(
                "{wide} of {} rules match any traffic between their zones, so segmentation \
                 stops at zone granularity",
                user.len()
            ),
            "narrow the rules that only need one host or one port",
        ));
    }
    out
}

// ---- exposure ---------------------------------------------------------------

fn exposure(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    let active: Vec<&Value> = i.forwards.iter().filter(|f| flag(f, "enabled")).collect();

    let unlogged = active.iter().filter(|f| !flag(f, "log")).count();
    if unlogged > 0 {
        out.push(finding(
            Severity::Medium,
            "exposure",
            "inbound traffic is accepted without a trace",
            format!("{unlogged} active port forward(s) have logging off"),
            "turn logging on for every forward: it is the only record that a connection \
             through them ever happened",
        ));
    }

    let open = active
        .iter()
        .filter(|f| !flag(f, "src_limiting_enabled"))
        .count();
    if open > 0 {
        out.push(finding(
            Severity::Medium,
            "exposure",
            "inbound rules accept any source",
            format!("{open} active port forward(s) have no source restriction"),
            "restrict the source where the service is not meant for the whole internet",
        ));
    }

    if i.settings
        .get("usg")
        .is_some_and(|u| flag(u, "upnp_enabled"))
    {
        out.push(finding(
            Severity::High,
            "exposure",
            "hosts may publish their own ports",
            "UPnP is enabled on the gateway, so any host can open an inbound port without \
             asking anyone",
            "disable UPnP and declare the forwards you actually want",
        ));
    }
    out
}

// ---- detection and logging --------------------------------------------------

fn detection(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(ips) = i.settings.get("ips") {
        let categories = ips
            .get("enabled_categories")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        if categories == 0 {
            out.push(finding(
                Severity::High,
                "detection",
                "intrusion prevention inspects nothing",
                "the engine is on and no signature category is selected, so the interface \
                 reads as protected while nothing is examined",
                "select the signature categories that match what this site runs, or turn the \
                 engine off so it stops claiming to protect",
            ));
        }
    }

    if let Some(r) = i.settings.get("rsyslogd") {
        if flag(r, "enabled") && text(r, "ip").is_empty() {
            out.push(finding(
                Severity::Medium,
                "detection",
                "logs do not leave the console",
                "logging is on but nothing is forwarded, so the record disappears with the \
                 console, which is the case an investigation needs it for",
                "forward syslog to a host that is not the console",
            ));
        }
    }

    if i.settings
        .get("super_smtp")
        .is_some_and(|m| !flag(m, "enabled"))
    {
        out.push(finding(
            Severity::Low,
            "detection",
            "no alert leaves the console",
            "mail alerting is not configured, so anything the console notices is only seen \
             by someone who opens it",
            "configure an alert destination",
        ));
    }
    out
}

// ---- inventory --------------------------------------------------------------

fn inventory(i: &Input) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut eol = Vec::new();
    let mut behind = Vec::new();
    let mut stale = Vec::new();

    for d in &i.devices {
        let p = firmware::assess(d);
        let name = text(d, "name");
        if p.eol || p.unsupported {
            eol.push(name.clone());
        }
        if p.below_minimum {
            behind.push(name.clone());
        } else if p.upgradable {
            stale.push(name);
        }
    }

    if !eol.is_empty() {
        out.push(finding(
            Severity::High,
            "inventory",
            "hardware past end of support",
            format!(
                "{} device(s) receive no further fix whatever their firmware says: {}",
                eol.len(),
                eol.join(", ")
            ),
            "plan their replacement; a current firmware on an unsupported model is still a \
             dead end",
        ));
    }
    if !behind.is_empty() {
        out.push(finding(
            Severity::High,
            "inventory",
            "firmware below the minimum the controller accepts",
            behind.join(", "),
            "upgrade these first: the vendor itself considers the running version too old",
        ));
    }
    if !stale.is_empty() {
        out.push(finding(
            Severity::Low,
            "inventory",
            "a newer firmware is available",
            stale.join(", "),
            "upgrade when convenient",
        ));
    }
    out
}

// ---- helpers ----------------------------------------------------------------

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
    use serde_json::json;

    fn with_settings(pairs: Vec<(&str, Value)>) -> Input {
        Input {
            settings: pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn ssh_without_a_key_is_critical_only_when_the_password_is_readable() {
        let readable = with_settings(vec![(
            "mgmt",
            json!({"x_ssh_enabled": true, "x_ssh_keys": [], "x_ssh_password": "hunter2"}),
        )]);
        assert_eq!(credentials(&readable)[0].severity, Severity::Critical);

        let hidden = with_settings(vec![(
            "mgmt",
            json!({"x_ssh_enabled": true, "x_ssh_keys": []}),
        )]);
        assert_eq!(credentials(&hidden)[0].severity, Severity::Medium);
    }

    #[test]
    fn ssh_with_a_key_installed_is_not_a_finding() {
        let keyed = with_settings(vec![(
            "mgmt",
            json!({"x_ssh_enabled": true, "x_ssh_keys": ["ssh-ed25519 AAA"]}),
        )]);
        assert!(credentials(&keyed)
            .iter()
            .all(|f| f.area != "credentials" || !f.title.contains("password and no key")));
    }

    #[test]
    fn a_rule_pointing_at_an_empty_zone_is_reported_as_not_in_force() {
        // The case worth catching: the rule reads as a restriction and does
        // nothing, so what it meant to restrict is decided somewhere else.
        let i = Input {
            zones: vec![json!({"id": "empty", "name": "Z-200", "networkIds": []})],
            policies: vec![json!({
                "name": "ALICE TO SECU",
                "metadata": {"origin": "USER_DEFINED"},
                "source": {"zoneId": "live"},
                "destination": {"zoneId": "empty"}
            })],
            ..Default::default()
        };
        let f = segmentation(&i);
        let dead = f
            .iter()
            .find(|f| f.title.contains("matches nothing"))
            .unwrap();
        assert_eq!(dead.severity, Severity::High);
        assert!(dead.detail.contains("ALICE TO SECU"));
    }

    #[test]
    fn a_system_rule_on_an_empty_zone_is_not_your_problem() {
        let i = Input {
            zones: vec![json!({"id": "empty", "name": "Dmz", "networkIds": []})],
            policies: vec![json!({
                "name": "Block All Traffic",
                "metadata": {"origin": "SYSTEM_DEFINED"},
                "source": {"zoneId": "empty"},
                "destination": {"zoneId": "empty"}
            })],
            ..Default::default()
        };
        assert!(segmentation(&i)
            .iter()
            .all(|f| !f.title.contains("matches nothing")));
    }

    #[test]
    fn prevention_with_no_category_is_raised_and_a_disabled_engine_is_not() {
        let armed = with_settings(vec![("ips", json!({"enabled_categories": ["malware"]}))]);
        assert!(detection(&armed)
            .iter()
            .all(|f| !f.title.contains("inspects nothing")));

        let hollow = with_settings(vec![("ips", json!({"enabled_categories": []}))]);
        assert!(detection(&hollow)
            .iter()
            .any(|f| f.title.contains("inspects nothing")));
    }

    #[test]
    fn findings_come_back_worst_first() {
        let i = Input {
            wlans: vec![json!({"name": "w", "pmf_mode": "optional", "wpa3_transition": true})],
            ..with_settings(vec![(
                "mgmt",
                json!({"x_ssh_enabled": true, "x_ssh_keys": [], "x_ssh_password": "x"}),
            )])
        };
        let all = run(&i);
        assert_eq!(all[0].severity, Severity::Critical);
        assert!(all.windows(2).all(|w| w[0].severity >= w[1].severity));
    }

    #[test]
    fn missing_data_produces_no_findings_and_is_reported_as_skipped() {
        let empty = Input::default();
        assert!(run(&empty).is_empty(), "absence is never a finding");
        assert_eq!(skipped(&empty).len(), 4, "and never a pass either");
    }
}
