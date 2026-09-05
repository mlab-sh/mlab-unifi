//! Rendering.
//!
//! The default is a plain, quiet terminal render: two-space indent, dimmed
//! labels, one blank line around each block. `-o json` switches every command
//! to raw JSON on stdout, untouched and parsable — nothing is humanized there,
//! so a pipeline always sees exactly what the API returned.

use std::sync::atomic::{AtomicU8, Ordering};

use colored::Colorize;
use serde_json::Value;

/// Longest cell a table will print before truncating; a UUID (36) still fits.
const MAX_CELL: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);

/// Resolve the format once at startup. Anything unknown means human.
pub fn init(format: Option<&str>) {
    let v = match format
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => 1,
        _ => 0,
    };
    FORMAT.store(v, Ordering::SeqCst);
}

pub fn format() -> Format {
    match FORMAT.load(Ordering::SeqCst) {
        1 => Format::Json,
        _ => Format::Human,
    }
}

pub fn is_json() -> bool {
    format() == Format::Json
}

/// A table column: a header plus the JSON paths to try, in order.
pub struct Col(pub &'static str, pub &'static [&'static str]);

pub const SITE_COLS: &[Col] = &[
    Col("NAME", &["name", "meta.name"]),
    Col("ID", &["id", "siteId"]),
    Col("REF", &["internalReference"]),
    Col("HOST", &["hostId"]),
];

/// Devices once the firmware posture is read. `ADVISORIES` is only filled when
/// the advisory list was consulted, and the renderer drops empty columns, so it
/// appears exactly when it means something.
pub const POSTURE_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("MODEL", &["model"]),
    Col("STATE", &["state"]),
    Col("FIRMWARE", &["firmwareVersion"]),
    Col("POSTURE", &["posture"]),
    Col("SUPPORT", &["support"]),
    Col("ADVISORIES", &["advisories"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
];

pub const DEVICE_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("MODEL", &["model"]),
    Col("STATE", &["state"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
    Col("FIRMWARE", &["firmwareVersion"]),
    Col("ID", &["id"]),
];

pub const CLIENT_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
    Col("TYPE", &["type"]),
    Col("ID", &["id"]),
];

/// The asset inventory: every known client, connected or not.
pub const INVENTORY_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("ACTIVE", &["activeNow"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
    Col("TYPE", &["type"]),
    Col("FIRST SEEN", &["firstSeen"]),
    Col("LAST SEEN", &["lastSeen"]),
];

/// The inventory once identities are resolved. `os` and `firstSeen` stay in the
/// JSON: eleven columns do not fit a terminal, and this view answers "what is
/// this thing", not "when did it appear".
pub const IDENTITY_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("ACTIVE", &["activeNow"]),
    Col("VENDOR", &["vendor"]),
    Col("DEVICE", &["deviceLabel", "device"]),
    Col("CONF", &["confidence"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
    Col("LAST SEEN", &["lastSeen"]),
];

/// The live listing once identities are resolved.
pub const LIVE_IDENTITY_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("VENDOR", &["vendor"]),
    Col("DEVICE", &["deviceLabel", "device"]),
    Col("CONF", &["confidence"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
    Col("TYPE", &["type"]),
];

/// Networks, read as a segmentation map.
pub const NETWORK_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("VLAN", &["vlanId"]),
    Col("SUBNET", &["subnet"]),
    Col("ZONE", &["zone"]),
    Col("ISOLATION", &["isolation"]),
    Col("INTERNET", &["internet"]),
    Col("MDNS", &["mdns"]),
    Col("UPNP", &["upnp"]),
];

/// Port forwards, read as the way in.
pub const FORWARD_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("PROTO", &["proto"]),
    Col("WAN PORT", &["wanPort"]),
    Col("TO", &["target"]),
    Col("ENABLED", &["enabled"]),
    Col("LOG", &["log"]),
    Col("SOURCE", &["source"]),
];

/// Firewall policies, read for hygiene rather than for configuration.
pub const POLICY_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("ACTION", &["action"]),
    Col("FROM", &["from"]),
    Col("TO", &["to"]),
    Col("LOG", &["log"]),
    Col("ON", &["enabled"]),
    Col("ORIGIN", &["origin"]),
];

/// SSID posture. `PSK` carries the shape of the key, never the key.
pub const WLAN_COLS: &[Col] = &[
    Col("SSID", &["name"]),
    Col("SECURITY", &["security"]),
    Col("WPA3", &["wpa3"]),
    Col("PMF", &["pmf"]),
    Col("PSK", &["psk"]),
    Col("ISOLATION", &["isolation"]),
    Col("GUEST", &["guest"]),
    Col("ON", &["enabled"]),
];

/// Access points in range, closest first.
pub const NEIGHBOUR_COLS: &[Col] = &[
    Col("SSID", &["essid"]),
    Col("BSSID", &["bssid"]),
    Col("GHZ", &["band"]),
    Col("CH", &["channel"]),
    Col("WIDTH", &["width"]),
    Col("SECURITY", &["security"]),
    Col("DBM", &["signal"]),
    Col("VENDOR", &["vendor"]),
    Col("SEEN", &["seenSecondsAgo"]),
];

/// Wired clients that can bridge a network, found by fingerprint rather than
/// by radio.
pub const BRIDGE_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("MAC", &["macAddress"]),
    Col("FAMILY", &["family"]),
    Col("DEVICE", &["device"]),
    Col("CONF", &["confidence"]),
    Col("IP", &["lastIp"]),
];

/// Radio occupancy. `OTHERS` is the interference figure.
pub const AIRTIME_COLS: &[Col] = &[
    Col("DEVICE", &["device"]),
    Col("GHZ", &["radio"]),
    Col("CH", &["channel"]),
    Col("WIDTH", &["width"]),
    Col("CLIENTS", &["clients"]),
    Col("BUSY%", &["busyPct"]),
    Col("SELF%", &["selfPct"]),
    Col("OTHERS%", &["othersPct"]),
    Col("RETRIES%", &["retriesPct"]),
    Col("DBM", &["txPower"]),
];

/// Arrivals: what the console met for the first time inside the window.
pub const SHADOW_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("APPEARED", &["firstSeen"]),
    Col("LAST SEEN", &["lastSeen"]),
    Col("LINK", &["link"]),
    Col("NETWORK", &["network"]),
    Col("VENDOR", &["vendor"]),
    Col("DEVICE", &["device"]),
    Col("MAC", &["macAddress"]),
];

/// UniFi hardware that joined the managed network in the same window.
pub const ADOPTION_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("MODEL", &["model"]),
    Col("ADOPTED", &["adoptedAt"]),
    Col("IP", &["ipAddress"]),
    Col("MAC", &["macAddress"]),
];

/// Posture checks: one row per thing looked at.
pub const POSTURE_CHECK_COLS: &[Col] = &[
    Col("AREA", &["area"]),
    Col("CHECK", &["check"]),
    Col("STATE", &["state"]),
    Col("DETAIL", &["detail"]),
];

/// Zones reachable from a starting point.
pub const BLAST_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("REACHES", &["reaches"]),
    Col("HOSTS", &["hosts"]),
    Col("NETWORKS", &["networks"]),
];

/// Audit findings, worst first.
pub const AUDIT_COLS: &[Col] = &[
    Col("SEVERITY", &["severity"]),
    Col("AREA", &["area"]),
    Col("FINDING", &["finding"]),
];

/// What a snapshot collects.
pub const RESOURCE_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("SURFACE", &["surface"]),
    Col("PATH", &["path"]),
    Col("ABOUT", &["about"]),
];

pub const SNAPSHOT_COLS: &[Col] = &[Col("SNAPSHOT", &["snapshot"]), Col("KB", &["kb"])];

/// What changed between two snapshots.
pub const DIFF_COLS: &[Col] = &[
    Col("RESOURCE", &["resource"]),
    Col("CHANGE", &["change"]),
    Col("ITEM", &["item"]),
    Col("DETAIL", &["detail"]),
];

pub const ZONE_COLS: &[Col] = &[
    Col("ZONE", &["name"]),
    Col("ORIGIN", &["origin"]),
    Col("NETWORKS", &["networks"]),
];

pub const HOST_COLS: &[Col] = &[
    Col("NAME", &["reportedState.hostname", "reportedState.name"]),
    Col("TYPE", &["type"]),
    Col("IP", &["ipAddress", "reportedState.ip"]),
    Col("ID", &["id", "hostId"]),
];

// ---- blocks -----------------------------------------------------------------

/// A section title, printed above a block.
pub fn heading(text: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", text.bold());
}

/// The count line closing a list.
pub fn count(n: usize, noun: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", format!("{n} {}", plural(noun, n)).dimmed());
}

/// English plural, enough for the nouns this CLI counts.
fn plural(noun: &str, n: usize) -> String {
    if n == 1 {
        return noun.to_string();
    }
    match noun.chars().last() {
        // "policy" -> "policies", but "day" -> "days": only a consonant before
        // the y takes the -ies form.
        Some('y') if !noun.ends_with(['a', 'e', 'i', 'o', 'u', 'y']) => noun.to_string(),
        Some('y') => format!("{}ies", &noun[..noun.len() - 1]),
        Some('s') | Some('x') | Some('z') => format!("{noun}es"),
        _ => format!("{noun}s"),
    }
}

/// An aligned key/value block, for status output the CLI composes itself
/// rather than reading from the API.
pub fn pairs(rows: &[(&str, String)]) {
    if is_json() {
        return;
    }
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    println!();
    for (k, v) in rows {
        println!("  {:<width$}  {}", k.dimmed(), tint(v));
    }
    println!();
}

/// Render one value: an object as a key/value block, anything else inline.
pub fn one(v: &Value) {
    if is_json() {
        print_json(v);
        return;
    }
    println!();
    block(v, 2);
    println!();
}

/// Render a list with known columns.
pub fn list(rows: &[Value], cols: &[Col]) {
    let spec: Vec<(String, Vec<String>)> = cols
        .iter()
        .map(|c| (c.0.to_string(), c.1.iter().map(|p| p.to_string()).collect()))
        .collect();
    render(rows, &spec);
}

/// Render a list whose shape is only known at runtime, i.e. `api ... --list`:
/// columns are the scalar fields of the first row.
pub fn list_auto(rows: &[Value]) {
    render(rows, &auto_spec(rows));
}

fn auto_spec(rows: &[Value]) -> Vec<(String, Vec<String>)> {
    const MAX_COLS: usize = 8;
    let Some(map) = rows.first().and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = map
        .iter()
        .filter(|(_, v)| !matches!(v, Value::Object(_) | Value::Array(_)))
        .map(|(k, _)| k)
        .collect();
    keys.sort_by_key(|k| (rank(k), k.to_string()));
    keys.into_iter()
        .take(MAX_COLS)
        .map(|k| (k.to_uppercase(), vec![k.clone()]))
        .collect()
}

fn render(rows: &[Value], spec: &[(String, Vec<String>)]) {
    if is_json() {
        print_json(&Value::Array(rows.to_vec()));
        return;
    }
    if rows.is_empty() || spec.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    // Keep only the columns that actually carry data on this console.
    let used: Vec<&(String, Vec<String>)> = spec
        .iter()
        .filter(|c| {
            let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
            rows.iter().any(|r| !first(r, &paths).is_empty())
        })
        .collect();
    if used.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            used.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&first(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = used.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    println!();
    let head: Vec<String> = used.iter().map(|c| c.0.clone()).collect();
    println!("  {}", pad_join(&head, &widths, |s| s.dimmed().to_string()));
    for row in &cells {
        println!("  {}", pad_join(row, &widths, |s| tint(s).to_string()));
    }
}

/// Pad every cell but the last to its column width, then colour it.
fn pad_join(cells: &[String], widths: &[usize], paint: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for (i, c) in cells.iter().enumerate() {
        out.push_str(&paint(c));
        if i + 1 != cells.len() {
            out.push_str(&" ".repeat(widths[i].saturating_sub(c.chars().count()) + 2));
        }
    }
    out.trim_end().to_string()
}

/// A key/value block, recursing into nested objects and tables of objects.
fn block(v: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    let Some(map) = v.as_object() else {
        println!("{pad}{}", tint(&scalar(v)));
        return;
    };

    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| (rank(k), k.to_string()));

    let width = keys
        .iter()
        .filter(|k| !matches!(map[**k], Value::Object(_) | Value::Array(_)))
        .map(|k| k.chars().count())
        .max()
        .unwrap_or(0);

    // Scalars first, so the identity of the thing is at the top of the block.
    for k in &keys {
        match &map[*k] {
            Value::Object(_) | Value::Array(_) => {}
            val => println!("{pad}{:<width$}  {}", k.dimmed(), tint(&humanize(k, val))),
        }
    }

    for k in &keys {
        // A branch that would print nothing but its own title is noise.
        if !has_content(&map[*k]) {
            continue;
        }
        match &map[*k] {
            Value::Array(items) if items.iter().all(|i| i.is_object()) => {
                println!();
                println!("{pad}{}", k.bold());
                let spec = auto_spec(items);
                for line in table_lines(items, &spec) {
                    println!("{pad}  {line}");
                }
            }
            Value::Array(items) => {
                let joined = items.iter().map(scalar).collect::<Vec<_>>().join(", ");
                println!("{pad}{:<width$}  {}", k.dimmed(), tint(&clip(&joined)));
            }
            Value::Object(_) => {
                println!();
                println!("{pad}{}", k.bold());
                block(&map[*k], indent + 2);
            }
            _ => {}
        }
    }
}

/// The lines of a sub-table, so a nested block can indent them.
fn table_lines(rows: &[Value], spec: &[(String, Vec<String>)]) -> Vec<String> {
    if spec.is_empty() {
        return Vec::new();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            spec.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&first(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = spec.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    let mut out = vec![pad_join(
        &spec.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        &widths,
        |s| s.dimmed().to_string(),
    )];
    out.extend(
        cells
            .iter()
            .map(|r| pad_join(r, &widths, |s| tint(s).to_string())),
    );
    out
}

/// Title for a detail block: the object's name when it has one, else the id.
pub fn name_of(v: &Value, id: &str) -> String {
    v.get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(id)
        .to_string()
}

/// Print raw JSON on stdout. The only thing `-o json` ever emits.
pub fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

// ---- helpers ----------------------------------------------------------------

/// Whether a value carries anything printable, however deeply nested.
fn has_content(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.values().any(has_content),
        Value::Array(a) => a.iter().any(has_content),
        Value::Null => false,
        _ => true,
    }
}

/// Identity fields float to the top of a block and to the left of a table.
fn rank(key: &str) -> u8 {
    match key {
        "name" | "idx" => 0,
        "id" => 1,
        "model" => 2,
        "state" => 3,
        "type" => 4,
        "ipAddress" => 5,
        "macAddress" => 6,
        "enabled" => 7,
        _ => 50,
    }
}

/// Colour a cell by what it says: statuses read faster than they scan.
fn tint(s: &str) -> colored::ColoredString {
    match s {
        "ONLINE" | "UP" | "CONNECTED" | "true" => s.green(),
        "OFFLINE" | "DOWN" | "DISCONNECTED" => s.red(),
        // `false` is an absence, not a fault — an inventory of disconnected
        // clients must not read as a wall of errors.
        "false" => s.dimmed(),
        "PENDING" | "UPDATING" | "ADOPTING" | "UNKNOWN" => s.yellow(),
        "current" | "supported" | "ok" => s.green(),
        "appeared" => s.yellow(),
        "disappeared" => s.dimmed(),
        "changed" => s.cyan(),
        "weak" | "medium" => s.yellow(),
        "critical" => s.red().bold(),
        "high" => s.red(),
        "low" => s.dimmed(),
        "unsupported" | "end of life" | "below minimum" => s.red(),
        "update available" => s.yellow(),
        "lts branch" | "unknown" => s.dimmed(),
        "" => s.normal(),
        _ => s.normal(),
    }
}

/// Units the API leaves raw. Only applied to unambiguously named keys, and only
/// in human mode — `-o json` keeps the original numbers.
fn humanize(key: &str, v: &Value) -> String {
    let raw = scalar(v);
    let Some(n) = v.as_f64() else { return raw };

    if key.ends_with("Pct") && (0.0..=100.0).contains(&n) {
        let filled = ((n / 10.0).round() as usize).min(10);
        let bar: String = "█".repeat(filled) + &"·".repeat(10 - filled);
        return format!("{n:>5.1}%  {}", bar.dimmed());
    }
    if key.ends_with("Bps") {
        return format!("{raw}  {}", format!("({})", bitrate(n)).dimmed());
    }
    if key.ends_with("Sec") && n >= 60.0 {
        return format!("{raw}  {}", format!("({})", duration(n as u64)).dimmed());
    }
    raw
}

fn bitrate(bps: f64) -> String {
    match bps {
        b if b >= 1e9 => format!("{:.1} Gb/s", b / 1e9),
        b if b >= 1e6 => format!("{:.1} Mb/s", b / 1e6),
        b if b >= 1e3 => format!("{:.1} kb/s", b / 1e3),
        b => format!("{b:.0} b/s"),
    }
}

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h{m:02}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// First non-empty value among `paths`, as a display string.
fn first(v: &Value, paths: &[&str]) -> String {
    for p in paths {
        if let Some(found) = dig(v, p) {
            let s = scalar(found);
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

/// Follow a dotted path into a JSON object.
fn dig<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// One-line rendering of a value; nested ones fall back to compact JSON.
fn scalar(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        // An empty list is an absence, not the two characters "[]", and a list
        // of scalars reads better as a list than as JSON.
        Value::Array(a) if a.is_empty() => String::new(),
        Value::Array(a) if a.iter().all(|i| !i.is_object() && !i.is_array()) => {
            a.iter().map(scalar).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// Truncate an over-long cell so one field cannot wreck the alignment.
fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_CELL {
        return s.to_string();
    }
    let kept: String = s.chars().take(MAX_CELL - 1).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_unknown_or_missing_format_falls_back_to_human() {
        init(None);
        assert_eq!(format(), Format::Human);
        init(Some("banana"));
        assert_eq!(format(), Format::Human);
        init(Some("JSON"));
        assert!(is_json(), "the format is matched case-insensitively");
        init(None);
    }

    #[test]
    fn auto_columns_are_scalars_only_with_identity_first() {
        let rows = vec![json!({"zzz": 1, "name": "ap", "ports": [{"idx": 1}], "id": "x"})];
        let cols: Vec<String> = auto_spec(&rows).into_iter().map(|c| c.0).collect();
        assert_eq!(
            cols,
            vec!["NAME", "ID", "ZZZ"],
            "nested fields stay out of the table"
        );
    }

    #[test]
    fn a_path_can_be_dotted_with_fallbacks() {
        let v = json!({"meta": {"name": "HQ"}});
        assert_eq!(first(&v, &["name", "meta.name"]), "HQ");
        assert_eq!(first(&v, &["nope"]), "");
    }

    #[test]
    fn units_are_only_added_to_unambiguous_keys() {
        assert!(humanize("cpuUtilizationPct", &json!(67.1)).starts_with(" 67.1%"));
        assert!(humanize("txRateBps", &json!(393791688.0)).contains("393.8 Mb/s"));
        assert!(humanize("uptimeSec", &json!(561466)).contains("6d 11h"));
        assert_eq!(
            humanize("idx", &json!(4)),
            "4",
            "a plain number is left alone"
        );
        assert_eq!(
            humanize("name", &json!("Pct")),
            "Pct",
            "strings are never rewritten"
        );
    }

    #[test]
    fn a_percentage_outside_the_scale_is_left_alone() {
        assert_eq!(humanize("weirdPct", &json!(420.0)), "420.0");
    }

    #[test]
    fn a_branch_with_nothing_in_it_is_not_printable() {
        assert!(!has_content(&json!({"switching": {"lags": []}})));
        assert!(!has_content(&json!({})));
        assert!(has_content(&json!({"switching": {"lags": [{"id": 1}]}})));
        assert!(
            has_content(&json!(false)),
            "false is a value, not an absence"
        );
    }

    #[test]
    fn nouns_are_pluralized_rather_than_suffixed() {
        assert_eq!(plural("device", 2), "devices");
        assert_eq!(plural("policy", 2), "policies", "not \"policys\"");
        assert_eq!(plural("client", 1), "client");
        assert_eq!(plural("zone", 0), "zones", "none is still plural");
    }

    #[test]
    fn lists_read_as_lists_and_an_empty_one_reads_as_nothing() {
        assert_eq!(scalar(&json!([])), "", "an empty list is an absence");
        assert_eq!(scalar(&json!(["CVE-1", "CVE-2"])), "CVE-1, CVE-2");
        assert_eq!(
            scalar(&json!([{"a": 1}])),
            "[{\"a\":1}]",
            "objects still fall back to JSON"
        );
    }

    #[test]
    fn long_cells_are_clipped_to_keep_columns_aligned() {
        let long = "x".repeat(80);
        assert_eq!(clip(&long).chars().count(), MAX_CELL);
        assert!(clip(&long).ends_with('…'));
        assert_eq!(clip("short"), "short");
    }
}
