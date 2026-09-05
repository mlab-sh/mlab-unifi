//! `diff` — what changed between two snapshots.
//!
//! This is the command the rest of the tool was built for. Every other view
//! reads a moment; this one reads the distance between two, which is where a
//! new device, an opened port and an edited rule stop being states and become
//! dated events.
//!
//! Three rules keep the output worth reading:
//!
//! * **Inventory is compared by presence, configuration field by field.** A
//!   client's counters and a neighbour's signal change every time anything is
//!   measured; comparing those field by field would bury one new device under a
//!   thousand meaningless deltas. The policy per resource lives in
//!   [`crate::unifi::registry`].
//! * **A resource that was unavailable in either snapshot is not comparable.**
//!   Never "everything disappeared".
//! * **Two snapshots of different consoles are refused**, on the identity the
//!   console reports rather than on the address it answered at.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::registry::{Compare, RESOURCES};

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// The older snapshot. Defaults to the second most recent for this console.
    pub before: Option<PathBuf>,
    /// The newer snapshot. Defaults to the most recent.
    pub after: Option<PathBuf>,
    /// Show every change, including ones with no security reading
    #[arg(long)]
    pub all: bool,
}

pub async fn run(ctx: &Ctx, a: &DiffArgs) -> Result<()> {
    let (before_path, after_path) = pick(a, &ctx.profile.host)?;
    let before = read(&before_path)?;
    let after = read(&after_path)?;

    let id = |s: &Value| {
        s.pointer("/console/id")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    match (id(&before), id(&after)) {
        // The address is not the identity: a console that changed address is
        // still the same console, and two different consoles that happen to
        // share an address are not.
        (Some(x), Some(y)) if x != y => {
            bail!("these snapshots are of different consoles ({x} and {y})")
        }
        _ => {}
    }

    let mut changes = Vec::new();
    let mut incomparable = Vec::new();

    for r in RESOURCES {
        let (b, aft) = (resource(&before, r.name), resource(&after, r.name));
        let key = match &r.compare {
            Compare::Skip => continue,
            Compare::Presence { key } | Compare::Fields { key, .. } => *key,
        };

        // Absent or unreadable on either side means the question cannot be
        // asked, which is not the same as an empty answer.
        let (Some(b), Some(aft)) = (b, aft) else {
            incomparable.push(r.name);
            continue;
        };

        let old = index(b, key);
        let new = index(aft, key);

        for (k, item) in &new {
            if !old.contains_key(k) {
                changes.push(change(r.name, "appeared", label(item, k), String::new()));
            }
        }
        for (k, item) in &old {
            if !new.contains_key(k) {
                changes.push(change(r.name, "disappeared", label(item, k), String::new()));
            }
        }

        if let Compare::Fields { watch, .. } = &r.compare {
            for (k, after_item) in &new {
                let Some(before_item) = old.get(k) else {
                    continue;
                };
                let deltas = fields(before_item, after_item, watch);
                if !deltas.is_empty() {
                    changes.push(change(
                        r.name,
                        "changed",
                        label(after_item, k),
                        deltas.join(", "),
                    ));
                }
            }
        }
    }

    changes.sort_by(|x, y| {
        weight(y)
            .cmp(&weight(x))
            .then(x["resource"].as_str().cmp(&y["resource"].as_str()))
    });
    let shown: Vec<&Value> = if a.all {
        changes.iter().collect()
    } else {
        changes.iter().filter(|c| weight(c) > 0).collect()
    };
    let rows: Vec<Value> = shown.iter().map(|c| (*c).clone()).collect();

    render::heading(&format!("{} to {}", stamp(&before), stamp(&after)));
    render::list(&rows, render::DIFF_COLS);
    render::count(rows.len(), "change");

    if render::is_json() {
        return Ok(());
    }

    if changes.is_empty() {
        ui::success("nothing changed between these two snapshots");
    } else if rows.len() < changes.len() {
        ui::info(&format!(
            "{} further change(s) with no security reading, add --all",
            changes.len() - rows.len()
        ));
    }

    if !incomparable.is_empty() {
        ui::warning(&format!(
            "{} resource(s) could not be compared because one side is missing or was \
             unreadable, which is not the same as unchanged: {}",
            incomparable.len(),
            incomparable.join(", ")
        ));
    }
    Ok(())
}

/// How much a change is worth reading.
///
/// Presence on the configuration resources is what an operator acts on; a
/// client coming and going is ordinary traffic.
fn weight(c: &Value) -> u8 {
    let resource = c["resource"].as_str().unwrap_or("");
    let kind = c["change"].as_str().unwrap_or("");
    match resource {
        "settings"
        | "wlans"
        | "port-forwards"
        | "firewall-policies"
        | "firewall-zones"
        | "networks"
        | "network-detail"
        | "traffic-matching-lists"
        | "sysinfo" => 2,
        "device-detail" | "devices" => 2,
        // A client that appeared is worth a look; one that left is not.
        "clients-known" if kind == "appeared" => 1,
        "neighbours" if kind == "appeared" => 1,
        _ => 0,
    }
}

fn change(resource: &str, kind: &str, item: String, detail: String) -> Value {
    json!({ "resource": resource, "change": kind, "item": item, "detail": detail })
}

/// The fields that differ, as `name: old -> new`.
fn fields(before: &Value, after: &Value, watch: &[&str]) -> Vec<String> {
    let names: Vec<String> = if watch.is_empty() {
        let mut all: BTreeSet<String> = BTreeSet::new();
        for v in [before, after] {
            if let Some(o) = v.as_object() {
                all.extend(o.keys().cloned());
            }
        }
        all.into_iter().collect()
    } else {
        watch.iter().map(|s| s.to_string()).collect()
    };

    names
        .iter()
        .filter_map(|f| {
            let (old, new) = (before.get(f), after.get(f));
            if old == new {
                return None;
            }
            Some(format!("{f}: {} -> {}", brief(old), brief(new)))
        })
        .collect()
}

fn brief(v: Option<&Value>) -> String {
    let s = match v {
        None | Some(Value::Null) => "absent".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    if s.chars().count() > 40 {
        format!("{}…", s.chars().take(39).collect::<String>())
    } else {
        s
    }
}

/// Items of one resource, by their identifying field.
fn index(resource: &Value, key: &str) -> BTreeMap<String, Value> {
    resource
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|i| {
                    let k = i.get(key)?;
                    let k = k
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| k.to_string());
                    Some((k, i.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Something a person can recognise, falling back to the identifier.
fn label(item: &Value, key: &str) -> String {
    for field in ["name", "hostname", "essid", "key"] {
        if let Some(s) = item.get(field).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    key.to_string()
}

/// A resource that was collected successfully, or nothing.
fn resource<'a>(snapshot: &'a Value, name: &str) -> Option<&'a Value> {
    let r = snapshot.pointer(&format!("/resources/{name}"))?;
    (r.get("status").and_then(Value::as_str) == Some("ok")).then_some(r)
}

fn stamp(s: &Value) -> String {
    s.get("takenAt")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

// ---- files ------------------------------------------------------------------

fn read(path: &Path) -> Result<Value> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not a snapshot", path.display()))?;

    match v.get("version").and_then(Value::as_i64) {
        Some(1) => Ok(v),
        // Refusing an unknown shape beats misreading it: that is what the
        // version field is for.
        Some(other) => bail!(
            "{} is a version {other} snapshot, this build reads version 1",
            path.display()
        ),
        None => bail!("{} has no version and is not a snapshot", path.display()),
    }
}

/// The two snapshots to compare: whatever was given, else the two most recent.
fn pick(a: &DiffArgs, host: &str) -> Result<(PathBuf, PathBuf)> {
    if let (Some(b), Some(aft)) = (&a.before, &a.after) {
        return Ok((b.clone(), aft.clone()));
    }
    if a.before.is_some() {
        bail!("give two snapshots, or none to compare the two most recent");
    }

    let safe: String = host
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let dir = crate::enrich::cache_dir().join("snapshots").join(safe);

    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("no snapshots in {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    found.sort();

    match found.len() {
        0 | 1 => bail!(
            "two snapshots are needed and {} exist(s) in {}; run `mlab-unifi snapshot` again \
             later",
            found.len(),
            dir.display()
        ),
        n => Ok((found[n - 2].clone(), found[n - 1].clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(items: Value) -> Value {
        json!({"items": items})
    }

    #[test]
    fn presence_is_read_from_the_identifying_field() {
        let old = index(&snap(json!([{"mac": "a", "name": "one"}])), "mac");
        let new = index(
            &snap(json!([{"mac": "a", "name": "one"}, {"mac": "b", "name": "two"}])),
            "mac",
        );
        assert!(!old.contains_key("b") && new.contains_key("b"));
    }

    #[test]
    fn only_the_watched_fields_are_compared() {
        // The point of the watch list: a device whose uptime moved has not
        // changed in any sense worth reporting.
        let before = json!({"version": "7.5.10", "uptime": 100});
        let after = json!({"version": "7.5.10", "uptime": 200});
        assert!(fields(&before, &after, &["version"]).is_empty());
        assert_eq!(
            fields(&before, &after, &[]).len(),
            1,
            "with no list, everything counts"
        );
    }

    #[test]
    fn a_changed_field_reads_as_old_to_new() {
        let d = fields(&json!({"log": false}), &json!({"log": true}), &["log"]);
        assert_eq!(d, vec!["log: false -> true"]);
    }

    #[test]
    fn an_appearing_field_is_shown_as_absent_before() {
        let d = fields(&json!({}), &json!({"log": true}), &["log"]);
        assert_eq!(d, vec!["log: absent -> true"]);
    }

    #[test]
    fn a_resource_that_failed_to_collect_is_not_readable() {
        let s = json!({"resources": {"x": {"status": "unavailable", "error": "404"}}});
        assert!(
            resource(&s, "x").is_none(),
            "unavailable must not read as empty"
        );

        let ok = json!({"resources": {"x": {"status": "ok", "items": []}}});
        assert!(resource(&ok, "x").is_some());
    }

    #[test]
    fn configuration_outranks_a_client_coming_and_going() {
        let rule = change("firewall-policies", "changed", "r".into(), String::new());
        let arrival = change("clients-known", "appeared", "c".into(), String::new());
        let departure = change("clients-known", "disappeared", "c".into(), String::new());
        assert!(weight(&rule) > weight(&arrival));
        assert_eq!(
            weight(&departure),
            0,
            "a client leaving is ordinary traffic"
        );
    }
}
